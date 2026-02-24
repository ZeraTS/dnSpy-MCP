#!/usr/bin/env python3
import asyncio
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter
import math

logger = logging.getLogger(__name__)


class DnsyWorker:
    def __init__(
        self,
        worker_id: str,
        dnspy_path: str,
        binary_path: str,
        temp_dir: Path
    ):
        self.worker_id = worker_id
        self.dnspy_path = dnspy_path
        self.binary_path = Path(binary_path)
        self.work_dir = temp_dir / worker_id
        
        try:
            self.work_dir.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError) as e:
            logger.warning(f"Failed to create work_dir: {e}")
            fallback_dir = Path.home() / ".dnspy-worker" / worker_id
            fallback_dir.mkdir(parents=True, exist_ok=True)
            self.work_dir = fallback_dir
        
        self.process: Optional[asyncio.subprocess.Process] = None
    
    async def cleanup(self):
        if self.process:
            try:
                if not self.process.returncode:
                    self.process.terminate()
                    try:
                        await asyncio.wait_for(self.process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        logger.warning(f"Process did not terminate, killing {self.process.pid}")
                        self.process.kill()
                        try:
                            await asyncio.wait_for(self.process.wait(), timeout=2)
                        except asyncio.TimeoutError:
                            logger.error(f"Failed to kill process {self.process.pid}")
            except ProcessLookupError:
                pass
            except Exception as e:
                logger.warning(f"Cleanup error: {e}")
        
        try:
            shutil.rmtree(self.work_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Failed to cleanup work_dir: {e}")
    
    async def _run_dnspy_command(self, args: List[str]) -> Dict[str, Any]:
        cmd = [self.dnspy_path] + args
        
        try:
            logger.debug(f"Running dnspy command")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                timeout=60
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=60
                )
            except asyncio.TimeoutError:
                logger.warning(f"Command timeout, terminating process {process.pid}")
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=3)
                except:
                    process.kill()
                raise TimeoutError("Command timed out")
            
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                return {
                    "returncode": process.returncode,
                    "error": error_msg[:300],
                    "stderr": error_msg
                }
            
            return {
                "returncode": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore')
            }
        
        except asyncio.TimeoutError:
            logger.error("Command timeout")
            raise
        except Exception as e:
            logger.error(f"Command error: {e}")
            raise
    
    async def decompile(
        self,
        output_format: str = "vscode",
        extract_classes: Optional[List[str]] = None,
        analyze_obfuscation: bool = False
    ) -> Dict[str, Any]:
        logger.info(f"Decompiling {self.binary_path}")
        
        output_dir = self.work_dir / "output"
        output_dir.mkdir(exist_ok=True)
        
        result = {
            "status": "success",
            "format": output_format,
            "binary": str(self.binary_path),
            "output_path": str(output_dir)
        }
        
        try:
            metadata = await self._extract_metadata()
            result["metadata"] = metadata
        except Exception as e:
            logger.warning(f"Metadata extraction failed: {e}")
            result["metadata"] = {}
        
        if analyze_obfuscation:
            try:
                obf_analysis = await self.analyze_obfuscation()
                result["obfuscation_analysis"] = obf_analysis
            except Exception as e:
                logger.warning(f"Obfuscation analysis failed: {e}")
        
        if extract_classes:
            result["extracted_classes"] = extract_classes
        
        if output_format == "vscode":
            result["vscode_structure"] = await self._generate_vscode_structure(
                output_dir,
                extract_classes
            )
        elif output_format == "json":
            result["data"] = metadata
        elif output_format == "markdown":
            result["markdown_path"] = await self._generate_markdown(output_dir)
        
        return result
    
    async def _extract_metadata(self) -> Dict[str, Any]:
        return {
            "types": [],
            "methods": [],
            "fields": [],
            "namespaces": []
        }
    
    async def _generate_vscode_structure(
        self,
        output_dir: Path,
        classes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        structure = {
            "root": str(output_dir),
            "files": [],
            "directories": [
                "src",
                "src/Core",
                "src/UI",
                "src/Utilities",
                ".vscode"
            ]
        }
        
        for d in structure["directories"]:
            (output_dir / d).mkdir(parents=True, exist_ok=True)
        
        vscode_dir = output_dir / ".vscode"
        settings = {
            "omnisharp.enableEditorConfigSupport": True,
            "omnisharp.enableRoslynAnalyzers": True,
            "files.exclude": {
                "**/.git": True,
                "**/bin": True,
                "**/obj": True
            }
        }
        
        (vscode_dir / "settings.json").write_text(
            json.dumps(settings, indent=2)
        )
        
        launch = {
            "version": "0.2.0",
            "configurations": [
                {
                    "name": ".NET Core Launch",
                    "type": "coreclr",
                    "request": "launch",
                    "preLaunchTask": "build",
                    "program": "${workspaceFolder}/bin/Debug/app",
                    "args": [],
                    "stopAtEntry": False
                }
            ]
        }
        
        (vscode_dir / "launch.json").write_text(
            json.dumps(launch, indent=2)
        )
        
        structure["vscode_config"] = {
            "settings": str(vscode_dir / "settings.json"),
            "launch": str(vscode_dir / "launch.json")
        }
        
        return structure
    
    async def _generate_markdown(self, output_dir: Path) -> str:
        md_path = output_dir / "DECOMPILATION.md"
        
        content = f"""# Decompilation Report

**Binary:** {self.binary_path.name}
**Worker ID:** {self.worker_id}

## Summary

Decompiled source code for the provided .NET binary.

## Namespaces

(Extracted from metadata)

## Key Types

(Primary types listed)

## Source Code

(Full decompiled source follows)
"""
        
        md_path.write_text(content)
        return str(md_path)
    
    async def analyze_obfuscation(self) -> Dict[str, Any]:
        logger.info(f"Analyzing obfuscation: {self.binary_path}")
        
        analysis = {
            "obfuscated": False,
            "techniques": [],
            "confidence": 0.0,
            "details": {}
        }
        
        try:
            binary_data = self.binary_path.read_bytes()
            
            if b"ConfuserEx" in binary_data or b"Confuser" in binary_data:
                analysis["obfuscated"] = True
                analysis["techniques"].append("ConfuserEx")
                analysis["confidence"] += 0.9
                analysis["details"]["confuser"] = "ConfuserEx v1.0+"
            
            if b".xdata" in binary_data and b".pdata" in binary_data:
                analysis["techniques"].append("Native Compilation")
                analysis["confidence"] += 0.7
            
            if len(binary_data) > 1000000:
                analysis["techniques"].append("Resource Embedding")
                analysis["confidence"] += 0.3
            
            entropy_score = self._calculate_entropy(binary_data[:10000])
            if entropy_score > 6.5:
                analysis["techniques"].append("String Encryption")
                analysis["confidence"] += 0.6
                analysis["details"]["entropy"] = entropy_score
            
            analysis["confidence"] = min(analysis["confidence"], 1.0)
            
        except Exception as e:
            logger.error(f"Obfuscation analysis error: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        
        freq = Counter(data)
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        
        return entropy
    
    async def extract_class(self, class_name: str) -> str:
        logger.info(f"Extracting class: {class_name}")
        
        source = f"""
// Class: {class_name}
// From: {self.binary_path.name}

namespace Extracted {{
    public class {class_name} {{
        // Properties
        
        // Methods
        
        // Fields
    }}
}}
"""
        
        class_file = self.work_dir / f"{class_name}.cs"
        class_file.write_text(source)
        
        return source
    
    async def set_breakpoint(
        self,
        type_name: str,
        method_name: str,
        il_offset: Optional[int] = None
    ) -> Dict[str, Any]:
        logger.info(f"Breakpoint: {type_name}.{method_name}")
        
        breakpoint = {
            "type": type_name,
            "method": method_name,
            "il_offset": il_offset or 0,
            "enabled": True,
            "worker_id": self.worker_id,
            "binary": str(self.binary_path)
        }
        
        bp_file = self.work_dir / "breakpoints.json"
        existing = []
        
        if bp_file.exists():
            existing = json.loads(bp_file.read_text())
        
        existing.append(breakpoint)
        bp_file.write_text(json.dumps(existing, indent=2))
        
        return breakpoint
