#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import click
import requests
import json
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

class DnspyClient:
    def __init__(self, host: str, port: int, api_key: str):
        self.base_url = f"http://{host}:{port}"
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key})

    def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        url = urljoin(self.base_url, endpoint)
        try:
            resp = self.session.request(method, url, timeout=300, **kwargs)
            if resp.status_code >= 400:
                try:
                    error = resp.json().get("error", resp.text)
                except:
                    error = resp.text
                raise click.ClickException(f"HTTP {resp.status_code}: {error}")
            return resp.json()
        except requests.exceptions.ConnectionError:
            raise click.ClickException(f"Cannot connect to {self.base_url}")
        except requests.exceptions.Timeout:
            raise click.ClickException("Request timeout")

    def decompile(self, binary_path: str, output_format: str = "vscode", analyze_obf: bool = False) -> dict:
        return self._request("POST", "/api/decompile", json={
            "binary_path": binary_path,
            "output_format": output_format,
            "analyze_obfuscation": analyze_obf
        })

    def analyze_obfuscation(self, binary_path: str) -> dict:
        return self._request("POST", "/api/analyze-obfuscation", json={"binary_path": binary_path})

    def extract_class(self, binary_path: str, class_name: str) -> dict:
        return self._request("POST", "/api/extract-class", json={
            "binary_path": binary_path,
            "class_name": class_name
        })

    def set_breakpoint(self, binary_path: str, type_name: str, method_name: str, il_offset: Optional[int] = None) -> dict:
        return self._request("POST", "/api/set-breakpoint", json={
            "binary_path": binary_path,
            "type_name": type_name,
            "method_name": method_name,
            "il_offset": il_offset
        })

    def batch_dump(self, binaries: list, output_format: str = "vscode", analyze_obf: bool = False) -> dict:
        return self._request("POST", "/api/batch-dump", json={
            "binaries": binaries,
            "output_format": output_format,
            "analyze_obfuscation": analyze_obf
        })

    def health(self) -> dict:
        return self._request("GET", "/health")

    def cleanup(self) -> dict:
        return self._request("POST", "/cleanup")

@click.group()
@click.option("--host", default="localhost", envvar="DNSPY_HOST", help="Daemon host")
@click.option("--port", default=9001, envvar="DNSPY_DAEMON_PORT", type=int, help="Daemon port")
@click.option("--api-key", envvar="DNSPY_API_KEY", help="API key")
@click.pass_context
def cli(ctx, host, port, api_key):
    if not api_key:
        api_key = "default-insecure-key-change-me"

    ctx.ensure_object(dict)
    ctx.obj["client"] = DnspyClient(host, port, api_key)

@cli.command()
@click.argument("binary_path")
@click.option("--format", "output_format", default="vscode", type=click.Choice(["vscode", "json", "markdown"]), help="Output format")
@click.option("--analyze-obf", is_flag=True, help="Analyze obfuscation")
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.pass_context
def decompile(ctx, binary_path, output_format, analyze_obf, json_output):
    """Decompile a .NET binary"""
    try:
        result = ctx.obj["client"].decompile(binary_path, output_format, analyze_obf)
        if json_output:
            click.echo(json.dumps(result, indent=2))
        else:
            click.echo(f"Status: {result['status']}")
            click.echo(f"Worker ID: {result.get('worker_id', 'N/A')}")
            if "result" in result:
                click.echo(f"Format: {result['result'].get('format', 'N/A')}")
                click.echo(f"Output: {result['result'].get('output_path', 'N/A')}")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

@cli.command()
@click.argument("binary_path")
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.pass_context
def analyze(ctx, binary_path, json_output):
    """Analyze obfuscation in a binary"""
    try:
        result = ctx.obj["client"].analyze_obfuscation(binary_path)
        if json_output:
            click.echo(json.dumps(result, indent=2))
        else:
            analysis = result.get("obfuscation_analysis", {})
            click.echo(f"Obfuscated: {analysis.get('obfuscated', False)}")
            click.echo(f"Confidence: {analysis.get('confidence', 0):.1%}")
            techniques = analysis.get("techniques", [])
            if techniques:
                click.echo("Techniques detected:")
                for t in techniques:
                    click.echo(f"  - {t}")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

@cli.command()
@click.argument("binary_path")
@click.argument("class_name")
@click.option("--output", "-o", help="Save to file")
@click.pass_context
def extract(ctx, binary_path, class_name, output):
    """Extract a class from a binary"""
    try:
        result = ctx.obj["client"].extract_class(binary_path, class_name)
        source = result.get("class_source", "")

        if output:
            Path(output).write_text(source)
            click.echo(f"Saved to {output}")
        else:
            click.echo(source)
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

@cli.command()
@click.argument("binary_path")
@click.argument("type_name")
@click.argument("method_name")
@click.option("--il-offset", type=int, help="IL offset")
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.pass_context
def breakpoint(ctx, binary_path, type_name, method_name, il_offset, json_output):
    """Set a breakpoint"""
    try:
        result = ctx.obj["client"].set_breakpoint(binary_path, type_name, method_name, il_offset)
        if json_output:
            click.echo(json.dumps(result, indent=2))
        else:
            bp = result.get("breakpoint", {})
            click.echo(f"Type: {bp.get('type', 'N/A')}")
            click.echo(f"Method: {bp.get('method', 'N/A')}")
            click.echo(f"IL Offset: {bp.get('il_offset', 'N/A')}")
            click.echo(f"Enabled: {bp.get('enabled', False)}")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

@cli.command()
@click.argument("binaries", nargs=-1, required=True)
@click.option("--format", "output_format", default="vscode", type=click.Choice(["vscode", "json", "markdown"]))
@click.option("--analyze-obf", is_flag=True, help="Analyze obfuscation for each")
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.pass_context
def batch(ctx, binaries, output_format, analyze_obf, json_output):
    """Batch process multiple binaries"""
    try:
        result = ctx.obj["client"].batch_dump(list(binaries), output_format, analyze_obf)
        if json_output:
            click.echo(json.dumps(result, indent=2))
        else:
            batch_results = result.get("batch_results", {})
            for binary, res in batch_results.items():
                status = res.get("status", "error")
                click.echo(f"{binary}: {status}")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

@cli.command()
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.pass_context
def status(ctx, json_output):
    """Check daemon health and status"""
    try:
        result = ctx.obj["client"].health()
        if json_output:
            click.echo(json.dumps(result, indent=2))
        else:
            click.echo(f"Status: {result.get('status', 'unknown')}")
            click.echo(f"Uptime: {result.get('uptime_seconds', 0):.0f}s")
            click.echo(f"Active Workers: {result.get('active_workers', 0)}/{result.get('worker_pool_size', 0)}")

            stats = result.get("stats", {})
            click.echo(f"\nRequests:")
            click.echo(f"  Total: {stats.get('total_requests', 0)}")
            click.echo(f"  Success: {stats.get('successful_requests', 0)}")
            click.echo(f"  Failed: {stats.get('failed_requests', 0)}")
            click.echo(f"  Success Rate: {stats.get('success_rate_percent', 0):.1f}%")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

@cli.command()
@click.confirmation_option(prompt="Are you sure?")
@click.pass_context
def cleanup(ctx):
    """Clean up all workers"""
    try:
        result = ctx.obj["client"].cleanup()
        click.echo(f"Cleaned up {result.get('cleaned_up', 0)} workers")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))

if __name__ == "__main__":
    cli(obj={})
