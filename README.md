# dnspy-mcp

[![GitHub License](https://img.shields.io/github/license/ZeraTS/dnspy-mcp?style=flat-square)](LICENSE)
[![GitHub Release](https://img.shields.io/github/release/ZeraTS/dnspy-mcp?style=flat-square)](https://github.com/ZeraTS/dnspy-mcp/releases)

MCP server for .NET binary decompilation and analysis via dnspy. Includes integrated CLI debugger for lightweight reflection and metadata extraction.

**Repository:** https://github.com/ZeraTS/dnspy-mcp

## Features

- Decompile .NET binaries (DLL/EXE)
- Detect and analyze obfuscation techniques (ConfuserEx, etc)
- Extract specific classes by name
- Set breakpoints for debugging
- Batch processing support
- VSCode project structure generation
- Markdown report export
- Worker pool for concurrent requests
- Integrated CLI debugger for reflection

## Installation

### Docker (Recommended)

```bash
docker-compose up
```

The daemon will start on `127.0.0.1:9001`.

### Manual Setup

**Quick Start:**
```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
export $(cat .env | xargs)
python3 daemon_improved.py
```

**Manual Install:**
```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your settings
export $(cat .env | xargs)
python3 daemon_improved.py  # Uses config.json + environment
```

Or use the basic daemon (minimal logging):
```bash
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

Returns detected techniques: ConfuserEx, string encryption, native compilation, entropy analysis.

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

## CLI Debugger

Lightweight reflection engine for .NET assembly inspection (does not require dnspy):

```bash
dotnet dnspy-debugger.dll --binary app.dll --list-types
dotnet dnspy-debugger.dll --binary app.dll --method Decrypt --json
dotnet dnspy-debugger.dll --binary app.dll --inspect System.String --json
```

Useful for:
- Quick metadata extraction
- Method discovery
- Type inspection
- JSON export for automation

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

## Known Issues & Workarounds

<details>
<summary><b>Obfuscation (ConfuserEx, CodeWall, etc)</b></summary>

### Problem
Obfuscated binaries have encrypted strings, renamed types, and IL code modification. Decompilation may fail or produce incomplete source.

### Detection
- Entropy analysis (> 6.5 indicates encryption)
- Presence of "ConfuserEx" or "Confuser" strings in binary
- Unusual method sizes or IL patterns

### Workaround
1. Use string decryption hooks if available
2. Frida runtime hooks to intercept decryption
3. Manual string extraction via breakpoints
4. Mono.Cecil IL disassembly (bypasses decompiler)
5. Dynamic analysis on instrumented VM

### Prevention
- Don't rely solely on decompiler output
- Cross-reference with dynamic analysis
- Check for tamper detection in decompiled code
- Use virtualization-aware tools

</details>

<details>
<summary><b>Virtualized Code (.NET Native, RyuJIT)</b></summary>

### Problem
Binaries compiled with .NET Native or aggressive JIT optimization lack IL code. dnspy cannot decompile to source.

### Detection
- `.xdata` and `.pdata` sections (native compilation markers)
- Small IL section, large native code section
- No managed metadata in sections

### Workaround
1. Use WinDbg or x64dbg for native disassembly
2. Frida to hook virtualized methods at runtime
3. Binary instrumentation (DynamoRIO, Pin)
4. IL disassembly of remaining managed code
5. Hex editor analysis of native code patterns

### Prevention
- Decompile pre-JIT binaries when possible
- Use version control to track source (easier than RE)
- Document critical algorithms
- Test decompiler output against known sources

</details>

<details>
<summary><b>Anti-Tamper Detection</b></summary>

### Problem
Binary checks for modifications (code integrity verification, hash checks). May exit or disable features if tampering detected.

### Detection
- Presence of hash verification in decompiled code
- PE header integrity checks
- Assembly signature validation
- Hard-coded checksums in code

### Workaround
1. Patch decompiled code to skip verification
2. Hook verification functions with Frida before they run
3. Modify binary sections that are NOT checked
4. Extract functionality without running modified binary
5. Use original binary with instrumentation (non-destructive)

### Prevention
- Analyze anti-tamper code before modification
- Instrument runtime rather than modifying binary
- Use separate unsigned copy for analysis
- Document verification logic
- Mock external verification calls

</details>

<details>
<summary><b>Anti-Debug Mechanisms</b></summary>

### Problem
Binaries detect debuggers and exit or change behavior. Includes:
- IsDebuggerPresent() checks
- OutputDebugString() traps
- Hardware breakpoint detection
- PEB manipulation checks
- Remote debugging detection

### Detection
- Search decompiled code for `Debugger.IsAttached`
- Look for `System.Diagnostics.Debugger` namespace usage
- Check Environment variables for debug flags
- Detect exception-based anti-debug (catch SEH)

### Workaround
1. Patch anti-debug calls before running
2. Run on non-debug CLR (release build)
3. Frida hooks to fake `IsAttached` = false
4. Use kernel-mode debugger (WinDbg) to bypass user-mode checks
5. Staticanalyze without executing
6. Use dnspy for static decompilation only

### Prevention
- Don't rely on debugger detection for security
- Use encryption + signature for sensitive code
- Separate anti-debug from main logic
- Make anti-debug checks expensive to bypass
- Log bypass attempts

</details>

<details>
<summary><b>Runtime Verification & Integrity Checks</b></summary>

### Problem
Code checks its own integrity at runtime, verifying IL hasn't changed. May throw exceptions or disable features.

### Detection
- Presence of `ComputeHash()` or `GetHash()` calls
- `.cctor` (static constructor) integrity checks
- Nested type verification
- Resource integrity validation

### Workaround
1. Extract pure algorithms before integrity check runs
2. Bypass check in decompiled version
3. Disable checks via Frida hooks
4. Replace checked IL with unchecked version
5. Use static analysis only (don't execute modified code)

### Prevention
- Don't check code at runtime for security
- Use cryptographic signing instead
- Distribute signed/sealed code (AppContainer)
- Document expected hashes separately
- Make integrity checks non-fatal

</details>

<details>
<summary><b>Virtualization & Process Isolation</b></summary>

### Problem
Binaries run in protected environments (AppContainer, sandbox, VM). Cannot access resources or inject code.

### Workaround
1. Run in matching environment (Docker container, VM)
2. Extract metadata without modification
3. Use static decompilation only
4. Cooperate with isolation mechanism (signed code)
5. Document expected behavior from outside environment

### Prevention
- Use container for legitimate testing
- Document isolation requirements
- Provide analysis tools inside environment
- Allow safe analysis modes
- Log analysis attempts for monitoring

</details>

<details>
<summary><b>Native C++ Mixed Assemblies</b></summary>

### Problem
.NET binaries with embedded C++ (P/Invoke, C++/CLI) cannot be fully decompiled. C++ portions require separate RE tools.

### Workaround
1. Use IDA Pro or Ghidra for native code
2. Extract IL-only methods via dnspy
3. Use Frida to hook native functions
4. Binary instrumentation for native code
5. Combine IL analysis + native disassembly

### Prevention
- Minimize native code in managed assemblies
- Document native API contracts
- Use P/Invoke stubs for interface
- Keep native and managed concerns separate
- Provide C++ headers or symbols when safe

</details>

## Improvements & Roadmap

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for:
- Configuration management
- Enhanced health checks
- Request logging & tracing
- CLI wrapper tool
- Caching & rate limiting
- Webhook notifications
- Web dashboard
- Performance optimization

Currently implemented:
- ✅ Config file support (JSON)
- ✅ Enhanced health endpoint (metrics, uptime, success rate)
- ✅ Request tracing with worker IDs
- ✅ Automated setup script
- ✅ Environment template (.env.example)

Planned:
- CLI wrapper (`dnspy-mcp decompile ...`)
- Request caching layer
- Rate limiting per API key
- Prometheus metrics endpoint
- Kubernetes deployment templates

## Testing

```bash
make build
make test
```

Or manually:

```bash
chmod +x test_api.sh
./test_api.sh
```

Check health with metrics:
```bash
curl http://localhost:9001/health | jq
```

## Development

For enhanced daemon features:
```bash
python3 daemon_improved.py
```

Features:
- Configuration file support
- Detailed health metrics
- Request statistics
- Worker pool monitoring

## License

MIT - See [LICENSE](LICENSE) for details.

## Support

- GitHub Issues: [Report bugs](https://github.com/ZeraTS/dnspy-mcp/issues)
- Discussions: [Ask questions](https://github.com/ZeraTS/dnspy-mcp/discussions)
