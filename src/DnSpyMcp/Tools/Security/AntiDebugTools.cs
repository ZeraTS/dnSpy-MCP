using System.ComponentModel;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using DnSpyMcp.Core;
using DnSpyMcp.Models;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Security;

[McpServerToolType]
public class AntiDebugTools
{
    private readonly AssemblyCache _cache;
    public AntiDebugTools(AssemblyCache cache) { _cache = cache; }

    [McpServerTool(Name = "detect_anti_debug"), Description("Fast static detection of anti-debug techniques via raw binary byte search and PE header inspection. Checks P/Invoke declarations, managed API usage, TLS callbacks, thread hiding, timing checks, hardware breakpoint detection, and exception-based patterns. No decompilation — completes in milliseconds.")]
    public List<AntiDebugFinding> DetectAntiDebug(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath)
    {
        var findings = new List<AntiDebugFinding>();
        try
        {
            var abs = Path.GetFullPath(assemblyPath);
            if (!File.Exists(abs)) throw new FileNotFoundException($"Not found: {abs}");

            var (_, peFile) = _cache.GetOrLoad(assemblyPath);
            var raw = File.ReadAllBytes(abs);

            findings.AddRange(ScanApiNames(raw));
            findings.AddRange(ScanManagedApis(raw));
            findings.AddRange(ScanTlsCallbacks(peFile));
            findings.AddRange(ScanILPatterns(raw, peFile));
        }
        catch (Exception ex)
        {
            findings.Add(new AntiDebugFinding("Error", "AnalysisError", "Assembly-level", ex.Message, "Low"));
        }

        return findings
            .GroupBy(f => f.Technique + "|" + f.Location)
            .Select(g => g.First())
            .OrderByDescending(f => f.Severity)
            .ToList();
    }

    private static readonly (string Api, string Category, string Severity, string Detail)[] ApiSignatures =
    [
        ("IsDebuggerPresent",          "PInvoke",           "High",   "kernel32 anti-debug check"),
        ("CheckRemoteDebuggerPresent", "PInvoke",           "High",   "Remote debugger detection"),
        ("NtQueryInformationProcess",  "PInvoke",           "High",   "ProcessDebugPort/ProcessDebugFlags query (ntdll)"),
        ("ZwQueryInformationProcess",  "PInvoke",           "High",   "NT-level process info query (ntdll)"),
        ("NtSetInformationThread",     "ThreadHiding",      "High",   "ThreadHideFromDebugger (0x11) — hides thread from debugger"),
        ("GetThreadContext",           "HardwareBreakpoint","Medium", "Thread context read — Dr0-Dr3 hardware breakpoint check"),
        ("NtGetContextThread",         "HardwareBreakpoint","Medium", "NT-level thread context read"),
        ("SetThreadContext",           "HardwareBreakpoint","Medium", "Thread context write — hardware breakpoint manipulation"),
        ("OutputDebugString",          "PInvoke",           "Medium", "Debugger presence probe via OutputDebugString error"),
        ("OutputDebugStringA",         "PInvoke",           "Medium", "Debugger presence probe (ANSI)"),
        ("OutputDebugStringW",         "PInvoke",           "Medium", "Debugger presence probe (Unicode)"),
        ("DebugBreak",                 "PInvoke",           "Medium", "Software breakpoint — triggers debugger if present"),
        ("DebugActiveProcess",         "PInvoke",           "Medium", "Debugger attachment API"),
        ("CreateToolhelp32Snapshot",   "PInvoke",           "Medium", "Process enumeration — debugger process scan"),
        ("Process32First",             "PInvoke",           "Medium", "Process enumeration — debugger process scan"),
        ("Process32Next",              "PInvoke",           "Medium", "Process enumeration — debugger process scan"),
        ("Process32FirstW",            "PInvoke",           "Medium", "Process enumeration (Unicode)"),
        ("Process32NextW",             "PInvoke",           "Medium", "Process enumeration (Unicode)"),
        ("NtRaiseHardError",           "Exception",         "Medium", "Hard error exception — exception-based anti-debug"),
        ("RaiseException",             "Exception",         "Medium", "Exception-based anti-debug"),
        ("QueryPerformanceCounter",    "Timing",            "Medium", "High-resolution timing — timing-based anti-debug"),
        ("GetTickCount",               "Timing",            "Medium", "Tick count timing check"),
        ("GetTickCount64",             "Timing",            "Medium", "Tick count timing check (64-bit)"),
        ("OpenProcess",                "PInvoke",           "Low",    "Process handle acquisition"),
    ];

    private static List<AntiDebugFinding> ScanApiNames(byte[] raw)
    {
        var findings = new List<AntiDebugFinding>();
        foreach (var (api, cat, sev, detail) in ApiSignatures)
        {
            if (ContainsUtf8(raw, api))
                findings.Add(new AntiDebugFinding(cat, api, "Metadata strings heap", detail, sev));
        }
        return findings;
    }

    private static List<AntiDebugFinding> ScanManagedApis(byte[] raw)
    {
        var findings = new List<AntiDebugFinding>();

        if (ContainsUtf8(raw, "get_IsAttached"))
            findings.Add(new AntiDebugFinding("ManagedAPI", "Debugger.IsAttached",
                "Metadata strings heap", "System.Diagnostics.Debugger.IsAttached property access", "High"));

        if (ContainsUtf8(raw, "get_IsLogging") || (ContainsUtf8(raw, "IsLogging") && ContainsUtf8(raw, "Debugger")))
            findings.Add(new AntiDebugFinding("ManagedAPI", "Debugger.IsLogging",
                "Metadata strings heap", "Debugger.IsLogging() call", "Low"));

        if (ContainsUtf8(raw, "FailFast"))
            findings.Add(new AntiDebugFinding("ManagedAPI", "Environment.FailFast",
                "Metadata strings heap", "Environment.FailFast — may terminate on integrity failure", "Medium"));

        if (ContainsUtf8(raw, "GetDelegateForFunctionPointer"))
            findings.Add(new AntiDebugFinding("ManagedAPI", "Dynamic P/Invoke",
                "Metadata strings heap", "Marshal.GetDelegateForFunctionPointer — dynamic native call, bypasses DllImport analysis", "Medium"));

        return findings;
    }

    private static List<AntiDebugFinding> ScanTlsCallbacks(ICSharpCode.Decompiler.Metadata.PEFile peFile)
    {
        var findings = new List<AntiDebugFinding>();
        try
        {
            var tlsDir = peFile.Reader.PEHeaders.PEHeader?.ThreadLocalStorageTableDirectory;
            if (tlsDir.HasValue && tlsDir.Value.RelativeVirtualAddress != 0)
                findings.Add(new AntiDebugFinding("TLSCallback", "TLS Callbacks Present",
                    "PE Header",
                    $"TLS directory RVA=0x{tlsDir.Value.RelativeVirtualAddress:X} — TLS callbacks execute before Main entry point",
                    "High"));
        }
        catch { }
        return findings;
    }

    private static List<AntiDebugFinding> ScanILPatterns(byte[] raw, ICSharpCode.Decompiler.Metadata.PEFile peFile)
    {
        var findings = new List<AntiDebugFinding>();
        if (ContainsUtf16LE(raw, " is tampered.") || ContainsUtf16LE(raw, "debugger detected"))
            findings.Add(new AntiDebugFinding("ManagedAPI", "Anti-Debug String Literal",
                "Unicode string heap",
                "Unicode anti-debug/tamper message found — likely displayed when debugger is detected",
                "High"));
        return findings;
    }

    private static bool ContainsUtf8(byte[] data, string value)
    {
        var pattern = System.Text.Encoding.UTF8.GetBytes(value);
        return data.AsSpan().IndexOf(pattern) >= 0;
    }

    private static bool ContainsUtf16LE(byte[] data, string value)
    {
        var pattern = System.Text.Encoding.Unicode.GetBytes(value);
        return data.AsSpan().IndexOf(pattern) >= 0;
    }
}
