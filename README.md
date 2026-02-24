# dnspy-mcp

MCP server for .NET binary decompilation and analysis via dnspy.

## Features

- Decompile .NET binaries (DLL/EXE)
- Detect and analyze obfuscation techniques (ConfuserEx, etc)
- Extract specific classes by name
- Set breakpoints for debugging
- Batch processing support
- VSCode project structure generation
- Markdown report export
- Worker pool for concurrent requests

## Installation

### Docker (Recommended)

```bash
docker-compose up
```

The daemon will start on `127.0.0.1:9001`.

### Manual Setup

```bash
pip install -r requirements.txt
export DNSPY_PATH=/opt/dnspy/dnSpy.exe
export DNSPY_API_KEY=your-secure-key
python3 daemon.py
```

## API

All endpoints require `X-API-Key` header.

### Decompile

```bash
curl -X POST http://localhost:9001/api/decompile \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/path/to/app.dll",
    "output_format": "vscode",
    "analyze_obfuscation": true
  }'
```

**Parameters:**
- `binary_path` (required): Path to .NET binary
- `output_format`: "vscode", "json", or "markdown"
- `extract_classes`: List of class names to extract
- `analyze_obfuscation`: Boolean to analyze obfuscation

### Analyze Obfuscation

```bash
curl -X POST http://localhost:9001/api/analyze-obfuscation \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "/path/to/app.dll"}'
```

### Extract Class

```bash
curl -X POST http://localhost:9001/api/extract-class \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/path/to/app.dll",
    "class_name": "MyNamespace.MyClass"
  }'
```

### Set Breakpoint

```bash
curl -X POST http://localhost:9001/api/set-breakpoint \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/path/to/app.dll",
    "type_name": "MyNamespace.MyClass",
    "method_name": "MyMethod",
    "il_offset": 0
  }'
```

### Batch Dump

```bash
curl -X POST http://localhost:9001/api/batch-dump \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "binaries": ["/path/to/app1.dll", "/path/to/app2.exe"],
    "output_format": "vscode"
  }'
```

### Health Check

```bash
curl http://localhost:9001/health
```

### Cleanup

```bash
curl -X POST http://localhost:9001/cleanup \
  -H "X-API-Key: your-key"
```

## MCP Server

Expose this daemon as an MCP server:

```bash
python3 mcp_server.py
```

The MCP server provides tool calls for:
- `decompile` - Full binary decompilation
- `analyze_obfuscation` - Detect obfuscation techniques
- `extract_class` - Extract specific class
- `set_breakpoint` - Create debug breakpoint
- `batch_dump` - Process multiple binaries
- `health_check` - Check daemon status
- `cleanup_workers` - Clean up all workers

## Configuration

Environment variables:

```bash
DNSPY_DAEMON_PORT=9001              # Daemon port
DNSPY_PATH=/opt/dnspy/dnSpy.exe    # Path to dnspy.exe
DNSPY_API_KEY=your-secure-key      # API key for authentication
```

## Architecture

- **daemon.py** - REST API server with worker pool
- **daemon_worker.py** - Individual worker processes
- **mcp_server.py** - MCP protocol wrapper
- **utils.py** - Utility functions

Each request spawns a worker that handles decompilation and cleanup.

## Security

- API key authentication required (set strong key)
- Localhost-only binding (127.0.0.1)
- Workers run isolated processes
- Automatic resource cleanup

Change `DNSPY_API_KEY` before production use.

## License

MIT
