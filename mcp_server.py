#!/usr/bin/env python3
import asyncio
import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import aiohttp
from mcp.server import Server
from mcp.types import TextContent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DAEMON_URL = "http://localhost:9001"
DAEMON_TIMEOUT = 120


class DnsyMCPServer:
    def __init__(self, daemon_url: str = DAEMON_URL):
        self.daemon_url = daemon_url
        self.server = Server("dnspy-mcp-server")
        self._setup_tools()
    
    def _setup_tools(self):
        @self.server.call_tool()
        async def decompile(
            binary_path: str,
            output_format: str = "vscode",
            extract_classes: list = None,
            analyze_obfuscation: bool = False
        ) -> list[TextContent]:
            """
            Decompile a .NET binary
            
            Args:
                binary_path: Path to .NET binary (DLL/EXE)
                output_format: "vscode", "json", or "markdown"
                extract_classes: List of class names to extract
                analyze_obfuscation: Analyze obfuscation techniques
            """
            return await self._call_daemon(
                "/api/decompile",
                {
                    "binary_path": binary_path,
                    "output_format": output_format,
                    "extract_classes": extract_classes or [],
                    "analyze_obfuscation": analyze_obfuscation
                }
            )
        
        @self.server.call_tool()
        async def analyze_obfuscation(binary_path: str) -> list[TextContent]:
            """Detect and analyze obfuscation techniques"""
            return await self._call_daemon(
                "/api/analyze-obfuscation",
                {"binary_path": binary_path}
            )
        
        @self.server.call_tool()
        async def extract_class(
            binary_path: str,
            class_name: str
        ) -> list[TextContent]:
            """Extract a specific class by name"""
            return await self._call_daemon(
                "/api/extract-class",
                {
                    "binary_path": binary_path,
                    "class_name": class_name
                }
            )
        
        @self.server.call_tool()
        async def set_breakpoint(
            binary_path: str,
            type_name: str,
            method_name: str,
            il_offset: int = None
        ) -> list[TextContent]:
            """Set breakpoint for debugging"""
            return await self._call_daemon(
                "/api/set-breakpoint",
                {
                    "binary_path": binary_path,
                    "type_name": type_name,
                    "method_name": method_name,
                    "il_offset": il_offset
                }
            )
        
        @self.server.call_tool()
        async def batch_dump(
            binaries: list,
            output_format: str = "vscode",
            analyze_obfuscation: bool = False
        ) -> list[TextContent]:
            """Process multiple binaries in batch"""
            return await self._call_daemon(
                "/api/batch-dump",
                {
                    "binaries": binaries,
                    "output_format": output_format,
                    "analyze_obfuscation": analyze_obfuscation
                }
            )
        
        @self.server.call_tool()
        async def health_check() -> list[TextContent]:
            """Check daemon health and status"""
            return await self._call_daemon_raw("/health", method="GET")
        
        @self.server.call_tool()
        async def cleanup_workers() -> list[TextContent]:
            """Clean up all active workers"""
            return await self._call_daemon_raw("/cleanup", method="POST")
    
    async def _call_daemon(
        self,
        endpoint: str,
        payload: dict
    ) -> list[TextContent]:
        url = urljoin(self.daemon_url, endpoint)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=DAEMON_TIMEOUT)
                ) as resp:
                    data = await resp.json()
                    
                    if resp.status >= 400:
                        error = data.get("error", "Unknown error")
                        return [TextContent(
                            type="text",
                            text=f"Error ({resp.status}): {error}"
                        )]
                    
                    return [TextContent(
                        type="text",
                        text=json.dumps(data, indent=2)
                    )]
        
        except asyncio.TimeoutError:
            return [TextContent(
                type="text",
                text="Error: Daemon request timed out"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]
    
    async def _call_daemon_raw(
        self,
        endpoint: str,
        method: str = "POST"
    ) -> list[TextContent]:
        url = urljoin(self.daemon_url, endpoint)
        
        try:
            async with aiohttp.ClientSession() as session:
                if method == "GET":
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as resp:
                        data = await resp.json()
                else:
                    async with session.post(
                        url,
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as resp:
                        data = await resp.json()
                
                return [TextContent(
                    type="text",
                    text=json.dumps(data, indent=2)
                )]
        
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]
    
    async def start(self):
        logger.info("Starting dnspy MCP server")
        await self.server.astart()


async def main():
    server = DnsyMCPServer()
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
