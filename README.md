# dnSpy-MCP

A Model Context Protocol server for static .NET assembly analysis powered by ICSharpCode.Decompiler (dnSpyEx engine). Exposes decompilation, IL disassembly, metadata inspection, and protection analysis as MCP tools over stdio. Never executes target assemblies.

## Requirements

- .NET 8 SDK or later
- Compatible MCP client (Claude Desktop, Cursor, or any client supporting MCP stdio transport)

## Installation

```
git clone https://github.com/ZeraTS/dnSpy-MCP.git
cd dnSpy-MCP
dotnet build src/DnSpyMcp/DnSpyMcp.csproj -c Release
```

## Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dnspy-mcp": {
      "command": "dotnet",
      "args": ["/path/to/src/DnSpyMcp/bin/Release/net8.0/DnSpyMcp.dll"]
    }
  }
}
```

## Tools

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `get_pe_info` | Get PE/COFF header information, assembly metadata, and target framework | `assemblyPath` |
| `get_resources` | List all manifest resources embedded in the assembly | `assemblyPath` |
| `resolve_token` | Resolve a metadata token (hex, e.g. `0x02000001`) to its definition | `assemblyPath`, `tokenHex` |
| `list_pinvokes` | List all P/Invoke (DllImport) declarations in the assembly | `assemblyPath` |
| `find_attributes` | Find all types and methods decorated with a specific attribute | `assemblyPath`, `attributeName` |
| `get_methods_for_type` | Get all methods defined on a specific type | `assemblyPath`, `typeName` |
| `decompile_assembly` | Decompile the entire assembly to C# source code | `assemblyPath` |
| `decompile_type` | Decompile a specific type to C# source code | `assemblyPath`, `typeName` |
| `decompile_method` | Decompile a specific method to C# source code | `assemblyPath`, `typeName`, `methodName` |
| `dump_il` | Dump IL (CIL) disassembly for the whole assembly, a type, or a specific method | `assemblyPath`, `typeName?`, `methodName?` |
| `inspect_type` | Inspect a type's structure: fields, methods, properties, interfaces, optionally with source | `assemblyPath`, `typeName`, `includeSource?` |
| `inspect_method` | Inspect a specific method: signature, parameters, decompiled source, optionally IL | `assemblyPath`, `typeName`, `methodName`, `includeSource?`, `includeIL?` |
| `list_types` | List all type definitions in the assembly | `assemblyPath` |
| `find_methods` | Find methods in the assembly, optionally filtered by name pattern | `assemblyPath`, `pattern?` |
| `search_strings` | Search for string literals in the assembly's decompiled source | `assemblyPath`, `pattern`, `useRegex?` |
| `search_members` | Search for types, methods, fields, and properties by name pattern | `assemblyPath`, `pattern` |
| `set_breakpoint` | Set a virtual breakpoint on a method at a specific IL offset | `assemblyPath`, `typeName`, `methodName`, `ilOffset` |
| `list_breakpoints` | List all active virtual breakpoints | |
| `inspect_breakpoint` | Show IL at a breakpoint offset, infer stack types, and find all callers of the method | `id` |
| `clear_breakpoints` | Remove all virtual breakpoints or a specific one by id | `id?` |
| `detect_anti_debug` | Static analysis to detect anti-debug techniques across 7 categories | `assemblyPath` |
| `detect_anti_tamper` | Static analysis to detect obfuscation and anti-tamper protections | `assemblyPath` |
| `get_protection_report` | Aggregate anti-debug and anti-tamper analysis into a report with risk score (0-10) and bypass recommendations | `assemblyPath` |

## Protection Analysis

`detect_anti_debug`, `detect_anti_tamper`, and `get_protection_report` perform static analysis only. The target assembly is never loaded as a .NET type, never JIT-compiled, and never executed. Analysis uses ICSharpCode.Decompiler's type system and PE reader exclusively.

### Anti-Debug Detection Categories

- P/Invoke declarations targeting known anti-debug APIs (IsDebuggerPresent, NtQueryInformationProcess, etc.)
- Managed API usage (System.Diagnostics.Debugger.IsAttached, etc.)
- Timing-based checks (Stopwatch, GetTickCount, QueryPerformanceCounter patterns)
- Thread hiding (NtSetInformationThread with ThreadHideFromDebugger)
- TLS callback presence (executes before Main entry point)
- Hardware breakpoint detection (CONTEXT Dr0-Dr3 reads)
- Exception-based anti-debug patterns

### Anti-Tamper Detection Categories

- Obfuscator fingerprinting (ConfuserEx, Dotfuscator, Eazfuscator, .NET Reactor, SmartAssembly, KoiVM, and 10+ more)
- Name obfuscation heuristics (control characters, zero-width characters, saturation)
- String encryption stubs (cctor array init patterns, int-to-string decrypt method signatures)
- Control flow obfuscation (switch proxies, high goto density)
- Integrity checks (self-hash, File.ReadAllBytes on own assembly, termination after hash comparison)
- VM/virtualisation (large switch dispatchers, encrypted IL stubs)
- Packing (PE section names: UPX, MPRESS, .vmp0, Themida, etc.)

### Risk Score

`get_protection_report` computes a risk score (0-10):

- High severity/confidence finding: +1.5 points
- Medium: +0.75 points
- Low: +0.25 points
- Capped at 10

## Project Structure

```
src/DnSpyMcp/
├── Program.cs
├── Core/
│   ├── AssemblyCache.cs        Thread-safe decompiler cache (keyed by path + mtime)
│   └── BreakpointRegistry.cs  In-memory virtual breakpoint store
├── Models/
│   └── Results.cs              All result record types
└── Tools/
    ├── Analysis/
    │   ├── AnalysisTools.cs    PE info, resources, token resolution, P/Invokes, attributes
    │   ├── BreakpointTools.cs  Virtual breakpoints: set, list, inspect, clear
    │   ├── DecompileTools.cs   C# decompilation, IL disassembly
    │   ├── InspectTools.cs     Type and method inspection
    │   └── SearchTools.cs      Type/method/member/string search
    └── Security/
        ├── AntiDebugTools.cs         Anti-debug pattern detection
        ├── AntiTamperTools.cs        Obfuscation and anti-tamper detection
        └── ProtectionReportTools.cs  Aggregated protection report
```

## Known Issues

<details>
<summary>Analysis of heavily obfuscated assemblies may produce false positives in name obfuscation heuristics</summary>

The name obfuscation detector flags members with single-letter names or compiler-generated names (containing `<` `>`). Standard .NET compiler-generated types (lambda closures, async state machines) will contribute to the obfuscated-name ratio. The threshold is set at 30% to reduce noise, but assemblies making heavy use of generics or LINQ may still trigger it.

</details>



<details>
<summary>String encryption detection requires obfuscated method names</summary>

The string decryption method detector only fires when the method name itself is obfuscated (contains control characters or is a single letter). If a protector uses readable method names for its string decrypt routines, this check will not detect them. The cctor array initialisation pattern is unaffected.

</details>

<details>
<summary>Assembly resolver errors on assemblies with missing dependencies</summary>

ICSharpCode.Decompiler attempts to resolve referenced assemblies from the same directory as the target. If dependencies are missing, decompilation of affected methods will fall back to partial output or skip. PE-level operations (`get_pe_info`, `get_resources`, `resolve_token`, `list_pinvokes`) are not affected. `ThrowOnAssemblyResolveErrors` is set to false by default to suppress resolver errors.

</details>

<details>
<summary>P/Invoke entry point detection is limited to DllImportAttribute</summary>

The `list_pinvokes` and anti-debug P/Invoke scanner only detect methods decorated with `[DllImport]`. Dynamic P/Invoke patterns using `NativeLibrary.Load` + `GetExport`, `GetProcAddress` via `Marshal`, or manually built delegate function pointers will not be detected.

</details>

## Credits

### Detect It Easy (DIE)

The protection detection logic in `Tools/Security/` draws directly from the detection approach used by [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) by horsicq.

DIE's core insight — that protector fingerprinting should operate on raw binary byte patterns, PE section metadata, and metadata string heap searches rather than decompiled source — is the foundation of the sub-millisecond detection performance in this project. Several obfuscator signatures (ConfuserEx, Eazfuscator, KoiVM, .NET Reactor, VMProtect, Dotfuscator, MPRESS, Themida, and others) are adapted from DIE's PE signature scripts under `db/PE/`. DIE is maintained by horsicq and contributors and is available under the MIT license.

### Anti-Debug Research

The anti-debug detection categories and API coverage are informed by:

- bengabay1994, [Anti-Debugging with .NET in Windows Environment](https://medium.com/@bengabay1994/anti-debugging-with-net-in-windows-environment-d5955e207c86) — PEB field checks (BeingDebugged, NtGlobalFlag, heap Flags/ForceFlags), StartupInfo.lpDesktop, NtCreateThreadEx thread hiding
- hsheric0210, [AntiDebug.NET](https://github.com/hsheric0210/AntiDebug.NET) — comprehensive .NET anti-debug and anti-VM technique reference covering dynamic IAT resolution, manual module mapping, and hook bypass patterns
- Check Point Research, [Anti-Debug Tricks](https://anti-debug.checkpoint.com/) — referenced via AntiDebug.NET
