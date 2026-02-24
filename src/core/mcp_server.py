#!/usr/bin/env python3
"""
dnspy-mcp MCP Server

Exposes all daemon endpoints as MCP tools with proper X-API-Key auth.
Connects to the daemon over HTTP — all requests are authenticated.
"""
import asyncio
import json
import logging
import os
from urllib.parse import urljoin

import aiohttp
from mcp.server import Server
from mcp.types import TextContent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DAEMON_URL    = os.getenv("DNSPY_DAEMON_URL", "http://localhost:9001")
API_KEY       = os.getenv("DNSPY_API_KEY", "")
DAEMON_TIMEOUT = int(os.getenv("DNSPY_REQUEST_TIMEOUT", "120"))

class DnsyMCPServer:
    def __init__(self, daemon_url: str = DAEMON_URL, api_key: str = API_KEY):
        if not api_key:
            raise ValueError(
                "DNSPY_API_KEY not set. MCP server cannot authenticate with the daemon."
            )
        self.daemon_url = daemon_url
        self.api_key = api_key
        self.server = Server("dnspy-mcp-server")
        self._setup_tools()

    @property
    def _headers(self) -> dict:
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }

    def _setup_tools(self):

        @self.server.call_tool()
        async def decompile(
            binary_path: str,
            output_format: str = "json",
            extract_classes: list = None,
            analyze_obfuscation: bool = False,
        ) -> list[TextContent]:
            """
            Decompile a .NET binary — returns types, PE info, and optionally
            extracted class sources and obfuscation analysis.

            Args:
                binary_path: Absolute path to .dll or .exe
                output_format: "json" | "markdown" | "vscode"
                extract_classes: List of fully-qualified class names to decompile
                analyze_obfuscation: Include obfuscation heuristics
            """
            return await self._post("/api/decompile", {
                "binary_path": binary_path,
                "output_format": output_format,
                "extract_classes": extract_classes or [],
                "analyze_obfuscation": analyze_obfuscation,
            })

        @self.server.call_tool()
        async def decompile_type(
            binary_path: str,
            type_name: str,
        ) -> list[TextContent]:
            """
            Decompile a specific type to C

            Args:
                binary_path: Path to .NET assembly
                type_name: Fully-qualified type name (e.g. "MyNamespace.MyClass")
            """
            return await self._post("/api/decompile-type", {
                "binary_path": binary_path,
                "type_name": type_name,
            })

        @self.server.call_tool()
        async def decompile_method(
            binary_path: str,
            type_name: str,
            method_name: str,
        ) -> list[TextContent]:
            """
            Decompile a specific method to C

            Args:
                binary_path: Path to .NET assembly
                type_name: Fully-qualified declaring type name
                method_name: Method name
            """
            return await self._post("/api/decompile-method", {
                "binary_path": binary_path,
                "type_name": type_name,
                "method_name": method_name,
            })

        @self.server.call_tool()
        async def dump_il(
            binary_path: str,
            type_name: str = None,
            method_name: str = None,
        ) -> list[TextContent]:
            """
            Dump raw IL bytecode for the whole assembly, a type, or a method.

            Args:
                binary_path: Path to .NET assembly
                type_name: Optional — restrict to this type
                method_name: Optional — restrict to this method (requires type_name)
            """
            return await self._post("/api/dump-il", {
                "binary_path": binary_path,
                "type_name": type_name,
                "method_name": method_name,
            })

        @self.server.call_tool()
        async def list_types(binary_path: str) -> list[TextContent]:
            """
            List all types in a .NET assembly with kind, namespace, and visibility.

            Args:
                binary_path: Path to .NET assembly
            """
            return await self._post("/api/list-types", {"binary_path": binary_path})

        @self.server.call_tool()
        async def list_methods(
            binary_path: str,
            type_name: str = None,
        ) -> list[TextContent]:
            """
            List methods in an assembly, optionally filtered to a specific type.

            Args:
                binary_path: Path to .NET assembly
                type_name: Optional — restrict to methods of this type
            """
            return await self._post("/api/list-methods", {
                "binary_path": binary_path,
                "type_name": type_name,
            })

        @self.server.call_tool()
        async def inspect_type(
            binary_path: str,
            type_name: str,
            include_source: bool = False,
        ) -> list[TextContent]:
            """
            Inspect a type — fields, methods, properties, base types, interfaces.

            Args:
                binary_path: Path to .NET assembly
                type_name: Fully-qualified type name
                include_source: Also return decompiled C
            """
            return await self._post("/api/inspect-type", {
                "binary_path": binary_path,
                "type_name": type_name,
                "include_source": include_source,
            })

        @self.server.call_tool()
        async def inspect_method(
            binary_path: str,
            type_name: str,
            method_name: str,
            include_il: bool = False,
        ) -> list[TextContent]:
            """
            Inspect a method — signature, parameters, decompiled C

            Args:
                binary_path: Path to .NET assembly
                type_name: Declaring type name
                method_name: Method name
                include_il: Also include raw IL bytecode
            """
            return await self._post("/api/inspect-method", {
                "binary_path": binary_path,
                "type_name": type_name,
                "method_name": method_name,
                "include_il": include_il,
            })

        @self.server.call_tool()
        async def search_strings(
            binary_path: str,
            pattern: str,
            use_regex: bool = False,
        ) -> list[TextContent]:
            """
            Search string literals across all method bodies (parses ldstr IL opcodes).
            Useful for finding hardcoded keys, URLs, credentials, or custom strings.

            Args:
                binary_path: Path to .NET assembly
                pattern: Search pattern (substring or regex)
                use_regex: Treat pattern as a regular expression
            """
            return await self._post("/api/search", {
                "binary_path": binary_path,
                "pattern": pattern,
                "kind": "string",
                "use_regex": use_regex,
            })

        @self.server.call_tool()
        async def search_members(
            binary_path: str,
            pattern: str,
        ) -> list[TextContent]:
            """
            Search types, methods, fields, and properties by name pattern.

            Args:
                binary_path: Path to .NET assembly
                pattern: Name substring to search for
            """
            return await self._post("/api/search", {
                "binary_path": binary_path,
                "pattern": pattern,
                "kind": "member",
            })

        @self.server.call_tool()
        async def pe_info(binary_path: str) -> list[TextContent]:
            """
            Get PE header info: architecture, target framework, CLR version,
            assembly name/version, code signing, section names.

            Args:
                binary_path: Path to .NET assembly
            """
            return await self._post("/api/pe-info", {"binary_path": binary_path})

        @self.server.call_tool()
        async def get_resources(binary_path: str) -> list[TextContent]:
            """
            List embedded manifest resources in the assembly.

            Args:
                binary_path: Path to .NET assembly
            """
            return await self._post("/api/get-resources", {"binary_path": binary_path})

        @self.server.call_tool()
        async def analyze_obfuscation(binary_path: str) -> list[TextContent]:
            """
            Detect obfuscation techniques: ConfuserEx, Dotfuscator, .NET Reactor,
            entropy analysis, native compilation indicators.

            Args:
                binary_path: Path to .NET assembly
            """
            return await self._post("/api/analyze-obfuscation", {"binary_path": binary_path})

        @self.server.call_tool()
        async def list_pinvokes(binary_path: str) -> list[TextContent]:
            """
            List all P/Invoke (native interop) method declarations.
            Useful for understanding native dependencies and attack surface.

            Args:
                binary_path: Path to .NET assembly
            """
            return await self._post("/api/list-pinvokes", {"binary_path": binary_path})

        @self.server.call_tool()
        async def find_attributes(
            binary_path: str,
            attribute_name: str,
        ) -> list[TextContent]:
            """
            Find all types and methods decorated with a specific attribute.

            Args:
                binary_path: Path to .NET assembly
                attribute_name: Attribute name or substring (e.g. "DllImport", "Obsolete")
            """
            return await self._post("/api/find-attributes", {
                "binary_path": binary_path,
                "attribute_name": attribute_name,
            })

        @self.server.call_tool()
        async def resolve_token(
            binary_path: str,
            token: str,
        ) -> list[TextContent]:
            """
            Resolve a raw metadata token (e.g. 0x06000001) to a type/method/field name.

            Args:
                binary_path: Path to .NET assembly
                token: Hex metadata token (e.g. "0x06000001")
            """
            return await self._post("/api/resolve-token", {
                "binary_path": binary_path,
                "token": token,
            })

        @self.server.call_tool()
        async def batch_dump(
            binaries: list,
            output_format: str = "json",
            analyze_obfuscation: bool = False,
        ) -> list[TextContent]:
            """
            Decompile multiple assemblies in one request.

            Args:
                binaries: List of absolute paths to .NET assemblies
                output_format: "json" | "markdown"
                analyze_obfuscation: Include obfuscation analysis for each binary
            """
            return await self._post("/api/batch-dump", {
                "binaries": binaries,
                "output_format": output_format,
                "analyze_obfuscation": analyze_obfuscation,
            })

        @self.server.call_tool()
        async def set_breakpoint(
            binary_path: str,
            type_name: str,
            method_name: str,
            il_offset: int = None,
        ) -> list[TextContent]:
            """
            Register a breakpoint at a type/method (+ optional IL offset).
            Requires an active debug session to activate.

            Args:
                binary_path: Path to .NET assembly
                type_name: Declaring type name
                method_name: Method name
                il_offset: Optional IL byte offset within the method body
            """
            return await self._post("/api/set-breakpoint", {
                "binary_path": binary_path,
                "type_name": type_name,
                "method_name": method_name,
                "il_offset": il_offset,
            })

        @self.server.call_tool()
        async def health_check() -> list[TextContent]:
            """Check daemon health, uptime, active workers, and feature flags."""
            return await self._get("/health")

        @self.server.call_tool()
        async def cleanup_workers() -> list[TextContent]:
            """Terminate and clean up all active worker processes."""
            return await self._post("/cleanup", {})

    async def _post(self, endpoint: str, payload: dict) -> list[TextContent]:
        url = urljoin(self.daemon_url, endpoint)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=DAEMON_TIMEOUT),
                ) as resp:
                    return await self._parse_response(resp)
        except asyncio.TimeoutError:
            return [TextContent(type="text", text=f"Error: Request to {endpoint} timed out")]
        except aiohttp.ClientConnectorError:
            return [TextContent(type="text",
                text=f"Error: Cannot connect to daemon at {self.daemon_url}. Is it running?")]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {e}")]

    async def _get(self, endpoint: str) -> list[TextContent]:
        url = urljoin(self.daemon_url, endpoint)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    return await self._parse_response(resp)
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {e}")]

    @staticmethod
    async def _parse_response(resp: aiohttp.ClientResponse) -> list[TextContent]:
        try:
            data = await resp.json()
        except Exception:
            text = await resp.text()
            data = {"raw": text}

        if resp.status == 401:
            return [TextContent(type="text",
                text="Error (401): Unauthorized — check DNSPY_API_KEY")]
        if resp.status >= 400:
            error = data.get("error", "Unknown error") if isinstance(data, dict) else str(data)
            return [TextContent(type="text", text=f"Error ({resp.status}): {error}")]

        return [TextContent(type="text", text=json.dumps(data, indent=2))]

    async def start(self):
        logger.info(f"Starting dnspy-mcp MCP server → daemon at {self.daemon_url}")
        await self.server.astart()

async def main():
    server = DnsyMCPServer()
    await server.start()

if __name__ == "__main__":
    asyncio.run(main())
