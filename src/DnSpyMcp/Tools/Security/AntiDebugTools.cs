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
        // Debugger presence — direct API
        ("IsDebuggerPresent",           "PEB",               "High",   "Reads PEB.BeingDebugged (offset 0x02) — most common debugger check"),
        ("CheckRemoteDebuggerPresent",  "PEB",               "High",   "Remote/cross-process debugger detection via NtQueryInformationProcess"),
        ("NtQueryInformationProcess",   "PEB",               "High",   "ProcessDebugPort(0x7) / ProcessDebugFlags(0x1F) / ProcessDebugObjectHandle(0x1E) query"),
        ("ZwQueryInformationProcess",   "PEB",               "High",   "NT-level alias for NtQueryInformationProcess"),

        // Thread hiding
        ("NtSetInformationThread",      "ThreadHiding",      "High",   "ThreadHideFromDebugger (0x11) — thread stops sending debug events"),
        ("NtCreateThreadEx",            "ThreadHiding",      "High",   "Direct thread creation — THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER (0x4) bypasses Thread class"),

        // Hardware breakpoint detection
        ("GetThreadContext",            "HardwareBreakpoint","High",   "Thread context read — checks Dr0-Dr3 for hardware breakpoints"),
        ("NtGetContextThread",          "HardwareBreakpoint","High",   "NT-level thread context — same as GetThreadContext"),
        ("SetThreadContext",            "HardwareBreakpoint","Medium", "Thread context write — clears or manipulates hardware breakpoints"),

        // PEB structure reads (direct memory)
        ("NtGlobalFlag",                "PEB",               "High",   "PEB.NtGlobalFlag (offset 0xBC) — set to 0x70 when process created by debugger"),
        ("BeingDebugged",               "PEB",               "High",   "PEB.BeingDebugged (offset 0x02) — direct PEB field read without IsDebuggerPresent"),
        ("PebBaseAddress",              "PEB",               "High",   "Direct PEB address access via NtQueryInformationProcess/ProcessBasicInformation"),
        ("GetProcessHeap",              "PEB",               "Medium", "Process heap flags check — Flags/ForceFlags set when created by debugger"),

        // Debugger output probe
        ("OutputDebugString",           "Exception",         "Medium", "GetLastError() probe — error differs depending on debugger presence"),
        ("OutputDebugStringA",          "Exception",         "Medium", "OutputDebugString ANSI variant"),
        ("OutputDebugStringW",          "Exception",         "Medium", "OutputDebugString Unicode variant"),

        // Software breakpoints / exceptions
        ("DebugBreak",                  "Exception",         "Medium", "Raises INT3 — crashes without debugger if unhandled"),
        ("SetUnhandledExceptionFilter", "Exception",         "Medium", "Overrides unhandled exception handler — used to detect single-step and INT3"),
        ("UnhandledExceptionFilter",    "Exception",         "Medium", "Direct call to default exception filter — exception-based anti-debug"),
        ("NtRaiseHardError",            "Exception",         "Medium", "Hard BSOD-style exception — exception-based anti-debug"),
        ("RaiseException",              "Exception",         "Medium", "Raises arbitrary exception codes — exception-based detection"),
        ("NtSetDebugFilterState",       "Exception",         "High",   "Blocks debug event delivery for specific exception types"),

        // Dynamic resolution (bypasses DllImport static scanning)
        ("GetProcAddress",              "DynamicResolution", "Medium", "Dynamic function resolution — may resolve anti-debug APIs without DllImport"),
        ("LdrGetProcedureAddress",      "DynamicResolution", "High",   "NT-level GetProcAddress — common in manual-IAT anti-debug to bypass hooks"),
        ("LoadLibrary",                 "DynamicResolution", "Low",    "Dynamic library loading — may load ntdll/kernel32 for unhooking"),
        ("LdrLoadDll",                  "DynamicResolution", "Medium", "NT-level LoadLibrary — manual module loading for hook bypass"),

        // Timing
        ("QueryPerformanceCounter",     "Timing",            "Medium", "High-resolution timing delta — execution slowdown under debugger"),
        ("GetTickCount",                "Timing",            "Medium", "Tick count timing check"),
        ("GetTickCount64",              "Timing",            "Medium", "Tick count timing check (64-bit)"),

        // Process/module enumeration (debugger process hunting)
        ("CreateToolhelp32Snapshot",    "ProcessEnum",       "Medium", "Snapshot for process/module enumeration — scans for debugger processes"),
        ("Process32First",              "ProcessEnum",       "Medium", "Process enumeration — walks process list for debugger"),
        ("Process32Next",               "ProcessEnum",       "Medium", "Process enumeration — walks process list for debugger"),
        ("Process32FirstW",             "ProcessEnum",       "Medium", "Process enumeration (Unicode)"),
        ("Process32NextW",              "ProcessEnum",       "Medium", "Process enumeration (Unicode)"),
        ("Module32First",               "ProcessEnum",       "Medium", "Module enumeration — scans loaded modules for debugger DLLs"),
        ("Module32Next",                "ProcessEnum",       "Medium", "Module enumeration — scans loaded modules for debugger DLLs"),
        ("EnumProcessModules",          "ProcessEnum",       "Medium", "Module enumeration via PSAPI"),

        // Window enumeration (debugger window title hunting)
        ("FindWindow",                  "WindowEnum",        "Medium", "Window title search — common pattern for detecting debugger windows"),
        ("FindWindowA",                 "WindowEnum",        "Medium", "FindWindow ANSI variant"),
        ("FindWindowW",                 "WindowEnum",        "Medium", "FindWindow Unicode variant"),
        ("FindWindowEx",                "WindowEnum",        "Medium", "Extended window search with class and title matching"),
        ("GetWindowText",               "WindowEnum",        "Low",    "Window text retrieval — may be used to read debugger window titles"),
        ("EnumWindows",                 "WindowEnum",        "Low",    "Window enumeration — iterates all top-level windows for debugger detection"),

        // Memory and patching
        ("VirtualQuery",                "Memory",            "Medium", "Memory page query — anti-memory-breakpoint detection"),
        ("VirtualProtect",              "Memory",            "Medium", "Memory protection change — may patch ntdll/kernel32 for unhooking"),
        ("WriteProcessMemory",          "Memory",            "High",   "Process memory write — may patch DbgBreakPoint or DbgUiRemoteBreakin"),
        ("DbgUiRemoteBreakin",          "Memory",            "High",   "Patching target — overwriting this in ntdll prevents debugger attach"),
        ("DbgBreakPoint",               "Memory",            "High",   "Software breakpoint target in ntdll — commonly patched to prevent attach"),

        // Debug privileges and handles
        ("DebugActiveProcess",          "Privileges",        "Medium", "Debugger process attachment"),
        ("OpenProcessToken",            "Privileges",        "Low",    "Token access — may check for SeDebugPrivilege"),
        ("AdjustTokenPrivileges",       "Privileges",        "Low",    "Privilege adjustment — may enable/check SeDebugPrivilege"),

        // Handle-based tricks
        ("OpenProcess",                 "HandleCheck",       "Low",    "Process handle acquisition"),
        ("CloseHandle",                 "Exception",         "Medium", "Invalid handle exception — CloseHandle(0xDEAD) triggers exception caught by debugger"),
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

        // Managed debugger API
        if (ContainsUtf8(raw, "get_IsAttached"))
            findings.Add(new AntiDebugFinding("ManagedAPI", "Debugger.IsAttached",
                "Metadata strings heap", "System.Diagnostics.Debugger.IsAttached — managed debugger presence check", "High"));

        if (ContainsUtf8(raw, "get_IsLogging") || (ContainsUtf8(raw, "IsLogging") && ContainsUtf8(raw, "Debugger")))
            findings.Add(new AntiDebugFinding("ManagedAPI", "Debugger.IsLogging",
                "Metadata strings heap", "Debugger.IsLogging() call", "Low"));

        if (ContainsUtf8(raw, "FailFast"))
            findings.Add(new AntiDebugFinding("ManagedAPI", "Environment.FailFast",
                "Metadata strings heap", "Environment.FailFast — immediate process termination, may be triggered by debug detection", "Medium"));

        // Dynamic P/Invoke patterns — bypass DllImport static scanning
        if (ContainsUtf8(raw, "GetDelegateForFunctionPointer"))
            findings.Add(new AntiDebugFinding("DynamicResolution", "Marshal.GetDelegateForFunctionPointer",
                "Metadata strings heap", "Dynamic native function call — anti-debug APIs may be resolved at runtime to evade static P/Invoke scanning", "Medium"));

        // PEB direct access patterns (from bengabay1994 / AntiDebug.NET patterns)
        if (ContainsUtf8(raw, "PebBaseAddress") || ContainsUtf8(raw, "ProcessBasicInformation"))
            findings.Add(new AntiDebugFinding("PEB", "Direct PEB Access",
                "Metadata strings heap", "PebBaseAddress or ProcessBasicInformation — direct PEB structure access for NtGlobalFlag/BeingDebugged reads", "High"));

        if (ContainsUtf8(raw, "NtGlobalFlag"))
            findings.Add(new AntiDebugFinding("PEB", "NtGlobalFlag Check",
                "Metadata strings heap", "PEB.NtGlobalFlag (0xBC) — set to 0x70 when process was created by a debugger (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)", "High"));

        if (ContainsUtf8(raw, "lpDesktop") || ContainsUtf8(raw, "StartupInfo"))
            findings.Add(new AntiDebugFinding("PEB", "StartupInfo.lpDesktop Check",
                "Metadata strings heap", "StartupInfo.lpDesktop — x64dbg sets this to empty string when it creates a process; used for specific debugger detection", "Medium"));

        if (ContainsUtf8(raw, "ForceFlags") || (ContainsUtf8(raw, "GetProcessHeap") && ContainsUtf8(raw, "Flags")))
            findings.Add(new AntiDebugFinding("PEB", "Process Heap Flags Check",
                "Metadata strings heap", "Heap.Flags/ForceFlags — set to HEAP_TAIL/FREE/VALIDATE_PARAMETERS when process created by debugger", "High"));

        // Debugger window title hunting
        var debuggerWindows = new[] { "OllyDbg", "x64dbg", "x32dbg", "WinDbg", "IDA", "Cheat Engine",
                                       "HxD", "Process Hacker", "Process Monitor", "Wireshark" };
        foreach (var wnd in debuggerWindows)
        {
            if (ContainsUtf8(raw, wnd) || ContainsUtf16LE(raw, wnd))
            {
                findings.Add(new AntiDebugFinding("WindowEnum", "Debugger Window Title Scan",
                    "Binary strings", $"Detected string {wnd} in binary — may be used with FindWindow to detect running debugger by window title", "High"));
                break;
            }
        }

        // Debugger module/process name scanning
        var debuggerProcs = new[] { "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
                                     "idaq.exe", "idaq64.exe", "idaw.exe", "idaw64.exe",
                                     "cheatengine", "processhacker", "procmon" };
        foreach (var proc in debuggerProcs)
        {
            if (ContainsUtf8(raw, proc) || ContainsUtf16LE(raw, proc))
            {
                findings.Add(new AntiDebugFinding("ProcessEnum", "Debugger Process Name Scan",
                    "Binary strings", $"Detected string {proc} in binary — process name comparison for debugger detection", "High"));
                break;
            }
        }

        // DbgUiRemoteBreakin / DbgBreakPoint patching
        if (ContainsUtf8(raw, "DbgUiRemoteBreakin") || ContainsUtf8(raw, "DbgBreakPoint"))
            findings.Add(new AntiDebugFinding("Memory", "ntdll Breakpoint Patching",
                "Metadata strings heap", "DbgUiRemoteBreakin or DbgBreakPoint — overwriting these in ntdll.dll prevents debugger from attaching", "High"));

        // SeDebugPrivilege check
        if (ContainsUtf8(raw, "SeDebugPrivilege"))
            findings.Add(new AntiDebugFinding("Privileges", "SeDebugPrivilege Check",
                "Metadata strings heap", "SeDebugPrivilege — checking for debug privilege presence or attempting to acquire it", "Medium"));

        return findings;
    }

    private static bool ContainsUtf16LE(byte[] data, string value)
    {
        var pattern = System.Text.Encoding.Unicode.GetBytes(value);
        return data.AsSpan().IndexOf(pattern) >= 0;
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

}
