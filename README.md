# dnspy-mcp

[![GitHub License](https://img.shields.io/github/license/ZeraTS/dnspy-mcp?style=flat-square)](LICENSE)
[![GitHub Release](https://img.shields.io/github/release/ZeraTS/dnspy-mcp?style=flat-square)](https://github.com/ZeraTS/dnspy-mcp/releases)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)](https://www.python.org/)

MCP server for .NET binary decompilation and analysis. Includes worker pool, caching, rate limiting, metrics, and integrated CLI debugger.

**Repository:** https://github.com/ZeraTS/dnspy-mcp

## Quick Start

### Docker
```bash
docker-compose up
```

### Manual Setup
```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
export $(cat .env | xargs)
python3 daemon_production.py
```

## Usage

### CLI Tool
```bash
python3 cli.py decompile /path/to/app.dll
python3 cli.py analyze /path/to/app.dll
python3 cli.py extract /path/to/app.dll System.String
python3 cli.py batch /path/to/*.dll
python3 cli.py status
```

### REST API
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

### Check Health
```bash
curl http://localhost:9001/health | jq
curl http://localhost:9001/metrics  # Prometheus format
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/decompile` | Decompile binary |
| POST | `/api/analyze-obfuscation` | Detect obfuscation |
| POST | `/api/extract-class` | Extract class by name |
| POST | `/api/set-breakpoint` | Create breakpoint |
| POST | `/api/batch-dump` | Batch process binaries |
| GET | `/health` | Health check & metrics |
| GET | `/metrics` | Prometheus metrics |
| POST | `/cleanup` | Clean up workers |

## Configuration

Edit `.env` or `config.json`:

```bash
DNSPY_DAEMON_PORT=9001
DNSPY_HOST=127.0.0.1
DNSPY_PATH=/opt/dnspy/dnSpy.exe
DNSPY_API_KEY=secure-key
DNSPY_WORKER_POOL_SIZE=5
DNSPY_REQUEST_TIMEOUT=120
```

Features can be toggled in `config.json`:
```json
{
  "features": {
    "enable_caching": true,
    "enable_rate_limiting": true,
    "enable_metrics": true,
    "enable_structured_logging": true,
    "enable_webhooks": false
  }
}
```

## Deployment

### Kubernetes
```bash
kubectl apply -f k8s-deployment.yaml
kubectl port-forward svc/dnspy-mcp 9001:9001
```

### Systemd
```bash
./setup.sh
sudo cp dnspy-mcp.service /etc/systemd/system/
sudo systemctl start dnspy-mcp
```

## Architecture

**Daemons:**
- `daemon.py` - Minimal (basic endpoints)
- `daemon_improved.py` - With config support
- `daemon_production.py` - Full features (caching, metrics, logging, webhooks)

**Core Modules:**
- `daemon_worker.py` - Worker process orchestration
- `caching.py` - SHA256-based request caching with TTL
- `ratelimit.py` - Token bucket rate limiting
- `metrics.py` - Prometheus metrics collection
- `structured_logging.py` - JSON logging with correlation IDs
- `webhooks.py` - Async webhook delivery
- `cli.py` - Command-line interface

**Utilities:**
- `mcp_server.py` - MCP protocol wrapper
- `utils.py` - Helper functions

## CLI Debugger

Lightweight reflection tool (no dnspy dependency):
```bash
dotnet build -c Release
dotnet bin/Release/net8.0/dnspy-mcp.dll --binary app.dll --list-types --json
dotnet bin/Release/net8.0/dnspy-mcp.dll --binary app.dll --method Decrypt --json
dotnet bin/Release/net8.0/dnspy-mcp.dll --binary app.dll --inspect System.String --json
```

## Known Issues

### Obfuscation (ConfuserEx, CodeWall, etc)
**Problem:** Encrypted strings, renamed types, IL modification. Decompilation may fail or be incomplete.

**Detection:** Entropy analysis (>6.5), "ConfuserEx"/"Confuser" string signatures, unusual method sizes.

**Workarounds:**
1. Use Frida hooks to intercept string decryption at runtime
2. Mono.Cecil IL disassembly (bypasses decompiler)
3. Dynamic analysis on instrumented VM
4. Manual breakpoint analysis for critical functions

### Virtualized Code (.NET Native, RyuJIT)
**Problem:** No IL code available. Binary compiled to native. dnspy cannot decompile.

**Detection:** `.xdata` and `.pdata` sections in PE, reduced IL section, large native code section.

**Workarounds:**
1. Use WinDbg or x64dbg for native disassembly
2. Frida to hook virtualized methods at runtime
3. Binary instrumentation (DynamoRIO, Pin)
4. IL disassembly of remaining managed code

### Anti-Tamper Detection
**Problem:** Binary checks for modifications. May exit or disable features if tampering detected.

**Detection:** Hash verification in decompiled code, PE header checks, assembly signature validation.

**Workarounds:**
1. Patch decompiled code to skip verification
2. Frida hooks to bypass before they run
3. Modify non-checked binary sections only
4. Instrument runtime rather than modifying binary
5. Use original binary with non-destructive instrumentation

### Anti-Debug Mechanisms
**Problem:** Detects debuggers and exits or changes behavior. IsDebuggerPresent, OutputDebugString traps, hardware breakpoint detection.

**Detection:** Search decompiled code for `Debugger.IsAttached`, `System.Diagnostics.Debugger`, debug environment variables.

**Workarounds:**
1. Patch anti-debug calls before running
2. Run on non-debug CLR (release build)
3. Frida hooks to fake `IsAttached` = false
4. Kernel-mode debugger (WinDbg) to bypass user-mode checks
5. Static analysis without execution

### Runtime Integrity Checks
**Problem:** Code verifies its own integrity at runtime. May throw or disable features.

**Detection:** `ComputeHash()`, `GetHash()` calls, `.cctor` (static constructor) checks, nested type verification.

**Workarounds:**
1. Extract pure algorithms before integrity check runs
2. Bypass check in decompiled version
3. Frida hooks to disable checks
4. Static analysis only (don't execute modified code)
5. Replace checked IL with unchecked version

### Process Isolation (AppContainer, Sandbox, VM)
**Problem:** Binary runs in protected environment. Cannot access resources or inject code.

**Workarounds:**
1. Run in matching environment (Docker, VM)
2. Extract metadata without modification
3. Use static decompilation only
4. Cooperate with isolation mechanism (signed code)
5. Document expected behavior from outside

### Native C++ Mixed Assemblies
**Problem:** .NET binaries with embedded C++ (P/Invoke, C++/CLI). C++ cannot be decompiled by dnspy.

**Workarounds:**
1. Use IDA Pro or Ghidra for native code
2. Extract IL-only methods via dnspy
3. Frida to hook native functions
4. Binary instrumentation for native code
5. Combine IL analysis + native disassembly

## Build

```bash
make build        # Install dependencies
make run-prod     # Run production daemon
make test         # Test API
make test-modules # Run unit tests
make cli          # Show CLI help
```

## Requirements

- Python 3.10+
- .NET SDK 8.0+ (for CLI debugger)
- dnspy.exe (for decompilation)

## License

MIT

## Support

- Issues: https://github.com/ZeraTS/dnspy-mcp/issues
- Discussions: https://github.com/ZeraTS/dnspy-mcp/discussions
