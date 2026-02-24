#!/usr/bin/env python3
"""
dnspy-mcp Worker

Calls the C
and returns structured JSON results. Never executes the target assembly —
all analysis is static.
"""
import asyncio
import json
import logging
import math
import os
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("dnspy-mcp.worker")

DEFAULT_CLI_SEARCH = [
    "/opt/dnspy-mcp/cli-debugger/bin/Release/net8.0/dnspy-mcp.dll",
    "/opt/dnspy-mcp/cli-debugger/bin/Debug/net8.0/dnspy-mcp.dll",
    str(Path.home() / ".dnspy-mcp/cli/dnspy-mcp.dll"),
]

CLI_PATH = os.getenv("DNSPY_CLI_PATH") or next(
    (p for p in DEFAULT_CLI_SEARCH if Path(p).exists()), None
)

DOTNET_CMD = os.getenv("DOTNET_PATH", "dotnet")
CLI_TIMEOUT = int(os.getenv("DNSPY_CLI_TIMEOUT", "60"))

async def _run_cli(args: List[str], timeout: int = CLI_TIMEOUT) -> Dict[str, Any]:
    """
    Invoke the C
    Returns parsed JSON dict or an error dict.
    """
    if not CLI_PATH:
        return {"error": "CLI tool not built. Run: cd cli-debugger && dotnet build -c Release"}

    cmd = [DOTNET_CMD, CLI_PATH, "--json"] + args
    logger.debug(f"CLI exec: {' '.join(cmd[:4])} ...")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"error": f"CLI timed out after {timeout}s"}

        stdout_str = stdout.decode("utf-8", errors="replace").strip()
        stderr_str = stderr.decode("utf-8", errors="replace").strip()

        if proc.returncode not in (0, None):
            return {
                "error": f"CLI exited with code {proc.returncode}",
                "stderr": stderr_str[:500],
            }

        if not stdout_str:
            return {"error": "CLI produced no output", "stderr": stderr_str[:500]}

        try:
            return json.loads(stdout_str)
        except json.JSONDecodeError:
            return {"content": stdout_str}

    except FileNotFoundError:
        return {"error": f"dotnet not found. Install .NET SDK 8+ (tried: {DOTNET_CMD})"}
    except Exception as e:
        logger.error(f"CLI error: {e}")
        return {"error": str(e)}

class DnsyWorker:
    def __init__(
        self,
        worker_id: str,
        dnspy_path: str,
        binary_path: str,
        temp_dir: Path,
    ):
        self.worker_id = worker_id
        self.binary_path = Path(binary_path)
        self.work_dir = temp_dir / worker_id
        self.process: Optional[asyncio.subprocess.Process] = None

        try:
            self.work_dir.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError) as e:
            logger.warning(f"Worker {worker_id}: work_dir fallback ({e})")
            fallback = Path.home() / ".dnspy-worker" / worker_id
            fallback.mkdir(parents=True, exist_ok=True)
            self.work_dir = fallback

    async def cleanup(self):
        if self.process:
            try:
                if self.process.returncode is None:
                    self.process.terminate()
                    try:
                        await asyncio.wait_for(self.process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        self.process.kill()
                        await asyncio.wait_for(self.process.wait(), timeout=2)
            except (ProcessLookupError, Exception) as e:
                logger.warning(f"Cleanup error: {e}")
        try:
            shutil.rmtree(self.work_dir, ignore_errors=True)
        except Exception:
            pass

    async def decompile(
        self,
        output_format: str = "json",
        extract_classes: Optional[List[str]] = None,
        analyze_obfuscation: bool = False,
    ) -> Dict[str, Any]:
        """
        Decompile an assembly. Returns structured JSON with metadata + optionally
        extracted classes and obfuscation analysis.
        """
        logger.info(f"Worker {self.worker_id}: decompile {self.binary_path.name}")

        result: Dict[str, Any] = {
            "status": "success",
            "binary": str(self.binary_path),
            "format": output_format,
        }

        meta = await _run_cli(["--binary", str(self.binary_path), "--list-types"])
        result["types"] = meta if isinstance(meta, list) else meta.get("error", meta)

        pe_info = await _run_cli(["--binary", str(self.binary_path), "--pe-info"])
        result["pe_info"] = pe_info

        if extract_classes:
            extracted = {}
            for cls in extract_classes:
                cls_src = await _run_cli([
                    "--binary", str(self.binary_path),
                    "--decompile-type", "--type", cls,
                ])
                extracted[cls] = cls_src.get("content", cls_src.get("error", ""))
            result["extracted_classes"] = extracted

        if analyze_obfuscation:
            result["obfuscation_analysis"] = await self.analyze_obfuscation()

        if output_format == "markdown":
            md_path = await self._generate_markdown(result)
            result["markdown_path"] = md_path
        elif output_format == "vscode":
            result["vscode_structure"] = await self._generate_vscode_structure()

        return result

    async def decompile_type(self, type_name: str) -> Dict[str, Any]:
        logger.info(f"Worker {self.worker_id}: decompile-type {type_name}")
        return await _run_cli([
            "--binary", str(self.binary_path),
            "--decompile-type", "--type", type_name,
        ])

    async def decompile_method(self, type_name: str, method_name: str) -> Dict[str, Any]:
        logger.info(f"Worker {self.worker_id}: decompile-method {type_name}.{method_name}")
        return await _run_cli([
            "--binary", str(self.binary_path),
            "--decompile-method", "--type", type_name, "--method", method_name,
        ])

    async def dump_il(
        self,
        type_name: Optional[str] = None,
        method_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        args = ["--binary", str(self.binary_path), "--dump-il"]
        if type_name:
            args += ["--type", type_name]
        if method_name:
            args += ["--method", method_name]
        return await _run_cli(args)

    async def search_strings(self, pattern: str, use_regex: bool = False) -> Dict[str, Any]:
        args = ["--binary", str(self.binary_path), "--search-string", pattern]
        if use_regex:
            args.append("--regex")
        return await _run_cli(args)

    async def search_members(self, pattern: str) -> Dict[str, Any]:
        return await _run_cli([
            "--binary", str(self.binary_path), "--search-member", pattern,
        ])

    async def list_types(self) -> Dict[str, Any]:
        return await _run_cli(["--binary", str(self.binary_path), "--list-types"])

    async def list_methods(self, type_name: Optional[str] = None) -> Dict[str, Any]:
        args = ["--binary", str(self.binary_path), "--list-methods"]
        if type_name:
            args += ["--type", type_name]
        return await _run_cli(args)

    async def extract_class(self, class_name: str) -> str:
        """Extract and decompile a class to C# source."""
        result = await _run_cli([
            "--binary", str(self.binary_path),
            "--decompile-type", "--type", class_name,
        ])
        return result.get("content", result.get("error", f"// Could not decompile {class_name}"))

    async def inspect_type(self, type_name: str, include_source: bool = False) -> Dict[str, Any]:
        args = ["--binary", str(self.binary_path), "--inspect", type_name]
        if include_source:
            args.append("--include-source")
        return await _run_cli(args)

    async def inspect_method(
        self,
        type_name: str,
        method_name: str,
        include_il: bool = False,
    ) -> Dict[str, Any]:
        args = [
            "--binary", str(self.binary_path),
            "--inspect-method",
            "--type", type_name,
            "--method", method_name,
            "--include-source",
        ]
        if include_il:
            args.append("--include-il")
        return await _run_cli(args)

    async def get_pe_info(self) -> Dict[str, Any]:
        return await _run_cli(["--binary", str(self.binary_path), "--pe-info"])

    async def get_resources(self) -> Dict[str, Any]:
        return await _run_cli(["--binary", str(self.binary_path), "--get-resources"])

    async def list_pinvokes(self) -> Dict[str, Any]:
        return await _run_cli(["--binary", str(self.binary_path), "--list-pinvokes"])

    async def find_attributes(self, attribute_name: str) -> Dict[str, Any]:
        return await _run_cli([
            "--binary", str(self.binary_path),
            "--find-attributes", attribute_name,
        ])

    async def resolve_token(self, token_hex: str) -> Dict[str, Any]:
        return await _run_cli([
            "--binary", str(self.binary_path), "--token", token_hex,
        ])

    async def set_breakpoint(
        self,
        type_name: str,
        method_name: str,
        il_offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Register a breakpoint definition. Actual breakpoint attachment requires
        a live debug session (see AutomatedDebugger — WIP for headless ptrace/CLR).
        For now this records the breakpoint so it can be applied when a session starts.
        """
        import json as _json
        bp = {
            "type": type_name,
            "method": method_name,
            "il_offset": il_offset or 0,
            "enabled": True,
            "worker_id": self.worker_id,
            "binary": str(self.binary_path),
            "note": "Breakpoint registered. Attach a debug session to activate.",
        }
        bp_file = self.work_dir / "breakpoints.json"
        existing = []
        if bp_file.exists():
            try:
                existing = _json.loads(bp_file.read_text())
            except Exception:
                pass
        existing.append(bp)
        bp_file.write_text(_json.dumps(existing, indent=2))
        return bp

    async def analyze_obfuscation(self) -> Dict[str, Any]:
        """
        Heuristic obfuscation detection via static binary inspection.
        Uses byte-pattern matching + entropy analysis. No execution.
        """
        logger.info(f"Worker {self.worker_id}: analyze-obfuscation {self.binary_path.name}")

        analysis: Dict[str, Any] = {
            "obfuscated": False,
            "techniques": [],
            "confidence": 0.0,
            "details": {},
        }

        try:
            data = self.binary_path.read_bytes()

            sigs = {
                b"ConfuserEx": ("ConfuserEx", 0.90),
                b"Confuser v": ("Confuser Classic", 0.85),
                b"dotfuscator": ("Dotfuscator", 0.85),
                b"SmartAssembly": ("SmartAssembly", 0.85),
                b"Obfuscar": ("Obfuscar", 0.80),
                b"Eazfuscator": ("Eazfuscator", 0.80),
                b"Babel.": ("Babel Obfuscator", 0.80),
                b"NetReactor": (".NET Reactor", 0.80),
                b"DeepSea": ("DeepSea Obfuscator", 0.75),
            }

            conf = 0.0
            for sig, (name, weight) in sigs.items():
                if sig.lower() in data.lower():
                    analysis["obfuscated"] = True
                    analysis["techniques"].append(name)
                    conf = max(conf, weight)
                    analysis["details"][name] = "Signature detected"

            if b".xdata" in data and b".pdata" in data:
                analysis["techniques"].append("NativeAOT/ReadyToRun")
                analysis["details"]["native"] = "PE sections .xdata/.pdata suggest native compilation"
                conf = max(conf, 0.60)

            entropy = _calculate_entropy(data[:16384])
            analysis["details"]["header_entropy"] = round(entropy, 4)
            if entropy > 7.0:
                analysis["techniques"].append("High entropy (packed/encrypted)")
                analysis["obfuscated"] = True
                conf = max(conf, 0.70)
            elif entropy > 6.5:
                analysis["techniques"].append("Elevated entropy (possible encryption)")
                conf = max(conf, 0.40)

            if len(data) > 2_000_000:
                analysis["details"]["size_mb"] = round(len(data) / 1_048_576, 2)
                analysis["techniques"].append("Large binary (possible embedded resources)")

            analysis["confidence"] = min(round(conf, 2), 1.0)
            if analysis["confidence"] > 0.5:
                analysis["obfuscated"] = True

        except Exception as e:
            logger.error(f"Obfuscation analysis error: {e}")
            analysis["error"] = str(e)

        return analysis

    async def _generate_markdown(self, result: Dict[str, Any]) -> str:
        md_path = self.work_dir / "DECOMPILATION.md"
        pe = result.get("pe_info", {})
        types = result.get("types", [])
        type_count = len(types) if isinstance(types, list) else "?"

        content = f"""# Decompilation Report

**Binary:** {self.binary_path.name}
**Worker ID:** {self.worker_id}

- Architecture: {pe.get('architecture', '?')}
- Framework: {pe.get('targetFramework', '?')}
- Version: {pe.get('assemblyVersion', '?')}
- Signed: {pe.get('isSigned', '?')}
- Managed: {pe.get('isManaged', '?')}

{chr(10).join(f'- `{t["fullName"]}`' for t in types[:50] if isinstance(t, dict)) if isinstance(types, list) else str(types)}

{f"... and {len(types) - 50} more." if isinstance(types, list) and len(types) > 50 else ""}

{result.get('obfuscation_analysis', {}).get('techniques', 'Not analyzed')}
"""
        md_path.write_text(content)
        return str(md_path)

    async def _generate_vscode_structure(self) -> Dict[str, Any]:
        import json as _json
        output_dir = self.work_dir / "output"
        for sub in ["src", ".vscode"]:
            (output_dir / sub).mkdir(parents=True, exist_ok=True)

        (output_dir / ".vscode" / "settings.json").write_text(_json.dumps({
            "omnisharp.enableEditorConfigSupport": True,
            "omnisharp.enableRoslynAnalyzers": True,
        }, indent=2))

        return {
            "root": str(output_dir),
            "vscode_config": str(output_dir / ".vscode" / "settings.json"),
        }

def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    entropy = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy
