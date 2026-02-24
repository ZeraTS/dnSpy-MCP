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
chmod +x tools/setup.sh
./tools/setup.sh
source venv/bin/activate
export $(cat config/.env | xargs)
python3 -m src.core.daemon
```

## Usage

### CLI Tool
```bash
python3 -m src.cli.cli decompile /path/to/app.dll
python3 -m src.cli.cli analyze /path/to/app.dll
python3 -m src.cli.cli extract /path/to/app.dll System.String
python3 -m src.cli.cli batch /path/to/*.dll
python3 -m src.cli.cli status
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

Edit `config/.env` or `config/config.json`:

```bash
DNSPY_DAEMON_PORT=9001
DNSPY_HOST=127.0.0.1
DNSPY_PATH=/opt/dnspy/dnSpy.exe
DNSPY_API_KEY=secure-key
DNSPY_WORKER_POOL_SIZE=5
DNSPY_REQUEST_TIMEOUT=120
```

Features can be toggled in `config/config.json`:
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
kubectl apply -f deploy/k8s-deployment.yaml
kubectl port-forward svc/dnspy-mcp 9001:9001
```

### Docker Compose
```bash
docker-compose -f deploy/docker-compose.yml up
```

## Project Structure

```
dnspy-mcp/
├── src/
│   ├── core/              # Daemon and worker
│   │   ├── daemon.py
│   │   ├── daemon_worker.py
│   │   └── mcp_server.py
│   ├── features/          # Optional features
│   │   ├── caching.py
│   │   ├── ratelimit.py
│   │   ├── metrics.py
│   │   └── webhooks.py
│   ├── utils/             # Utilities
│   │   ├── structured_logging.py
│   │   └── utils.py
│   └── cli/               # Command-line tool
│       └── cli.py
├── cli-debugger/          # C# .NET CLI tool
│   ├── src/
│   │   ├── AutomatedDebugger/
│   │   └── CLI/
│   └── dnspy-mcp.csproj
├── deploy/                # Deployment configs
│   ├── k8s-deployment.yaml
│   ├── docker-compose.yml
│   └── Dockerfile
├── config/                # Configuration
│   ├── config.json
│   └── .env.example
├── tools/                 # Scripts
│   ├── setup.sh
│   └── test_api.sh
├── tests/                 # Tests
│   └── test_modules.py
├── requirements.txt
└── README.md
```

## CLI Debugger

Lightweight reflection tool (no dnspy dependency):
```bash
cd cli-debugger
dotnet build -c Release
dotnet bin/Release/net8.0/dnspy-mcp.dll --binary app.dll --list-types --json
dotnet bin/Release/net8.0/dnspy-mcp.dll --binary app.dll --method Decrypt --json
```

## Build & Test

```bash
make build         # Install dependencies
make run           # Run daemon (full features)
make test          # Test API
make test-modules  # Run unit tests
```

## Known Issues

<details>
<summary><b>Obfuscation (ConfuserEx, CodeWall, etc)</b></summary>

**Problem:** Encrypted strings, renamed types, IL modification. Decompilation may fail or be incomplete.

**Detection:** Entropy analysis (>6.5), "ConfuserEx"/"Confuser" string signatures, unusual method sizes.

**Workarounds:**
- Frida hooks to intercept string decryption at runtime
- Mono.Cecil IL disassembly (bypasses decompiler)
- Dynamic analysis on instrumented VM
- Manual breakpoint analysis for critical functions
</details>

<details>
<summary><b>Virtualized Code (.NET Native, RyuJIT)</b></summary>

**Problem:** No IL code available. Binary compiled to native. dnspy cannot decompile.

**Detection:** `.xdata` and `.pdata` sections in PE, reduced IL section, large native code section.

**Workarounds:**
- WinDbg or x64dbg for native disassembly
- Frida to hook virtualized methods at runtime
- Binary instrumentation (DynamoRIO, Pin)
- IL disassembly of remaining managed code
</details>

<details>
<summary><b>Anti-Tamper Detection</b></summary>

**Problem:** Binary checks for modifications. May exit or disable features if tampering detected.

**Detection:** Hash verification in decompiled code, PE header checks, assembly signature validation.

**Workarounds:**
- Patch decompiled code to skip verification
- Frida hooks to bypass before they run
- Modify non-checked binary sections only
- Instrument runtime rather than modifying binary
- Use original binary with non-destructive instrumentation
</details>

<details>
<summary><b>Anti-Debug Mechanisms</b></summary>

**Problem:** Detects debuggers and exits or changes behavior. IsDebuggerPresent, OutputDebugString traps, hardware breakpoint detection.

**Detection:** Search decompiled code for `Debugger.IsAttached`, `System.Diagnostics.Debugger`, debug environment variables.

**Workarounds:**
- Patch anti-debug calls before running
- Run on non-debug CLR (release build)
- Frida hooks to fake `IsAttached` = false
- Kernel-mode debugger (WinDbg) to bypass user-mode checks
- Static analysis without execution
</details>

<details>
<summary><b>Runtime Integrity Checks</b></summary>

**Problem:** Code verifies its own integrity at runtime. May throw or disable features.

**Detection:** `ComputeHash()`, `GetHash()` calls, `.cctor` (static constructor) checks, nested type verification.

**Workarounds:**
- Extract pure algorithms before integrity check runs
- Bypass check in decompiled version
- Frida hooks to disable checks
- Static analysis only (don't execute modified code)
- Replace checked IL with unchecked version
</details>

<details>
<summary><b>Process Isolation (AppContainer, Sandbox, VM)</b></summary>

**Problem:** Binary runs in protected environment. Cannot access resources or inject code.

**Workarounds:**
- Run in matching environment (Docker, VM)
- Extract metadata without modification
- Use static decompilation only
- Cooperate with isolation mechanism (signed code)
- Document expected behavior from outside
</details>

<details>
<summary><b>Native C++ Mixed Assemblies</b></summary>

**Problem:** .NET binaries with embedded C++ (P/Invoke, C++/CLI). C++ cannot be decompiled by dnspy.

**Workarounds:**
- IDA Pro or Ghidra for native code
- Extract IL-only methods via dnspy
- Frida to hook native functions
- Binary instrumentation for native code
- Combine IL analysis + native disassembly
</details>

## Requirements

- Python 3.10+
- .NET SDK 8.0+ (for CLI debugger)
- dnspy.exe (for decompilation)

## License

MIT

## Support

- Issues: https://github.com/ZeraTS/dnspy-mcp/issues
- Discussions: https://github.com/ZeraTS/dnspy-mcp/discussions
