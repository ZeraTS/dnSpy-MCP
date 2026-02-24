using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Text.RegularExpressions;
using DnSpyMcp.Core;
using DnSpyMcp.Models;
using ICSharpCode.Decompiler.TypeSystem;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Security;

[McpServerToolType]
public class AntiDebugTools
{
    private readonly AssemblyCache _cache;

    public AntiDebugTools(AssemblyCache cache)
    {
        _cache = cache;
    }

    [McpServerTool(Name = "detect_anti_debug"), Description("Static analysis to detect anti-debug techniques: P/Invoke checks, managed API usage, timing tricks, TLS callbacks, hardware breakpoint detection, thread hiding, and exception-based anti-debug patterns")]
    public List<AntiDebugFinding> DetectAntiDebug(
        [Description("Absolute or relative path to the .NET assembly to analyse")] string assemblyPath)
    {
        var findings = new List<AntiDebugFinding>();
        try
        {
            var (decompiler, peFile) = _cache.GetOrLoad(assemblyPath);


            var pinvokeFindings = ScanPInvokeAntiDebug(decompiler);
            findings.AddRange(pinvokeFindings);


            var managedFindings = ScanManagedApiAntiDebug(decompiler);
            findings.AddRange(managedFindings);


            var timingFindings = ScanTimingAntiDebug(decompiler);
            findings.AddRange(timingFindings);


            var exceptionFindings = ScanExceptionAntiDebug(decompiler);
            findings.AddRange(exceptionFindings);


            var tlsFindings = ScanTLSCallbacks(peFile);
            findings.AddRange(tlsFindings);


            var hwBpFindings = ScanHardwareBreakpointDetection(decompiler);
            findings.AddRange(hwBpFindings);
        }
        catch (Exception ex)
        {
            findings.Add(new AntiDebugFinding("Error", "AnalysisError", "Assembly-level", ex.Message, "Low"));
        }

        return findings
            .GroupBy(f => f.Technique + "|" + f.Location)
            .Select(g => g.First())
            .ToList();
    }

    private static List<AntiDebugFinding> ScanPInvokeAntiDebug(ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler)
    {
        var findings = new List<AntiDebugFinding>();


        var pinvokeSeverity = new Dictionary<string, (string Category, string Severity)>(StringComparer.OrdinalIgnoreCase)
        {
            ["IsDebuggerPresent"]          = ("PInvoke", "High"),
            ["CheckRemoteDebuggerPresent"] = ("PInvoke", "High"),
            ["NtQueryInformationProcess"]  = ("PInvoke", "High"),
            ["ZwQueryInformationProcess"]  = ("PInvoke", "High"),
            ["NtSetInformationThread"]     = ("ThreadHiding", "High"),
            ["OutputDebugString"]          = ("PInvoke", "Medium"),
            ["OutputDebugStringA"]         = ("PInvoke", "Medium"),
            ["OutputDebugStringW"]         = ("PInvoke", "Medium"),
            ["DebugActiveProcess"]         = ("PInvoke", "Medium"),
            ["DebugBreak"]                 = ("PInvoke", "Medium"),
            ["GetThreadContext"]           = ("HardwareBreakpoint", "Medium"),
            ["SetThreadContext"]           = ("HardwareBreakpoint", "Medium"),
            ["NtGetContextThread"]         = ("HardwareBreakpoint", "Medium"),
            ["CreateToolhelp32Snapshot"]   = ("PInvoke", "Medium"),
            ["Process32First"]             = ("PInvoke", "Medium"),
            ["Process32Next"]              = ("PInvoke", "Medium"),
            ["Process32FirstW"]            = ("PInvoke", "Medium"),
            ["Process32NextW"]             = ("PInvoke", "Medium"),
            ["OpenProcess"]                = ("PInvoke", "Low"),
            ["NtRaiseHardError"]           = ("Exception", "Medium"),
            ["RaiseException"]             = ("Exception", "Medium"),
            ["CloseHandle"]                = ("Exception", "Medium"),
            ["QueryPerformanceCounter"]    = ("Timing", "Medium"),
            ["GetTickCount"]               = ("Timing", "Medium"),
            ["GetTickCount64"]             = ("Timing", "Medium"),
        };

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            foreach (var m in type.Methods)
            {
                try
                {
                    var dllImportAttr = m.GetAttributes()
                        .FirstOrDefault(a => a.AttributeType.Name == "DllImportAttribute");
                    if (dllImportAttr == null) continue;


                    var namedArgs = dllImportAttr.NamedArguments;
                    var epArg = namedArgs.FirstOrDefault(a => a.Name == "EntryPoint");
                    var entryPoint = epArg.Value?.ToString() ?? m.Name;


                    foreach (var kvp in pinvokeSeverity)
                    {
                        if (m.Name.Equals(kvp.Key, StringComparison.OrdinalIgnoreCase) ||
                            entryPoint.Equals(kvp.Key, StringComparison.OrdinalIgnoreCase))
                        {
                            string detail = $"DllImport declared in {type.FullName}";
                            if (entryPoint != m.Name) detail += $", entry point: {entryPoint}";
                            findings.Add(new AntiDebugFinding(
                                kvp.Value.Category,
                                kvp.Key,
                                $"{type.FullName}.{m.Name}",
                                detail,
                                kvp.Value.Severity));
                        }
                    }
                }
                catch { continue; }
            }
        }

        return findings;
    }

    private static List<AntiDebugFinding> ScanManagedApiAntiDebug(ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler)
    {
        var findings = new List<AntiDebugFinding>();

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                try
                {
                    var src = decompiler.DecompileAsString(method.MetadataToken);
                    var location = $"{type.FullName}.{method.Name}";


                    if (src.Contains("Debugger.IsAttached"))
                        findings.Add(new AntiDebugFinding("ManagedAPI", "Debugger.IsAttached",
                            location, "Checks System.Diagnostics.Debugger.IsAttached", "High"));


                    if (Regex.IsMatch(src, @"Debugger\.Break\s*\("))
                        findings.Add(new AntiDebugFinding("ManagedAPI", "Debugger.Break",
                            location, "Calls System.Diagnostics.Debugger.Break()", "Medium"));


                    if (Regex.IsMatch(src, @"Debugger\.Launch\s*\("))
                        findings.Add(new AntiDebugFinding("ManagedAPI", "Debugger.Launch",
                            location, "Calls System.Diagnostics.Debugger.Launch()", "Medium"));


                    if (Regex.IsMatch(src, @"Debugger\.IsLogging\s*\("))
                        findings.Add(new AntiDebugFinding("ManagedAPI", "Debugger.IsLogging",
                            location, "Calls System.Diagnostics.Debugger.IsLogging()", "Low"));


                    if (Regex.IsMatch(src, @"Environment\.FailFast\s*\("))
                        findings.Add(new AntiDebugFinding("ManagedAPI", "Environment.FailFast",
                            location, "Calls Environment.FailFast — may be triggered by integrity check", "Medium"));
                }
                catch { continue; }
            }
        }

        return findings;
    }

    private static List<AntiDebugFinding> ScanTimingAntiDebug(ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler)
    {
        var findings = new List<AntiDebugFinding>();

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                try
                {
                    var src = decompiler.DecompileAsString(method.MetadataToken);
                    var location = $"{type.FullName}.{method.Name}";


                    if (src.Contains("Stopwatch") && Regex.IsMatch(src, @"[><=!]{1,2}\s*\d+"))
                        findings.Add(new AntiDebugFinding("Timing", "Stopwatch-based timing check",
                            location, "Uses Stopwatch with threshold comparison — timing anti-debug pattern", "Medium"));


                    if ((src.Contains("Environment.TickCount") || src.Contains("TickCount64")) &&
                        Regex.IsMatch(src, @"[-+*/]"))
                        findings.Add(new AntiDebugFinding("Timing", "TickCount timing check",
                            location, "Uses Environment.TickCount in arithmetic — timing anti-debug pattern", "Medium"));


                    if ((src.Contains("DateTime.UtcNow") || src.Contains("DateTime.Now")) &&
                        Regex.IsMatch(src, @"\.Subtract|\.TotalMilliseconds|\.TotalSeconds|-\s*DateTime"))
                        findings.Add(new AntiDebugFinding("Timing", "DateTime timing check",
                            location, "Uses DateTime subtraction for elapsed time measurement — possible timing anti-debug", "Low"));
                }
                catch { continue; }
            }
        }

        return findings;
    }

    private static List<AntiDebugFinding> ScanExceptionAntiDebug(ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler)
    {
        var findings = new List<AntiDebugFinding>();

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                try
                {
                    var src = decompiler.DecompileAsString(method.MetadataToken);
                    var location = $"{type.FullName}.{method.Name}";


                    if (src.Contains("CloseHandle") && Regex.IsMatch(src, @"new IntPtr\s*\(\s*-?[012]\s*\)|IntPtr\.Zero"))
                        findings.Add(new AntiDebugFinding("Exception", "CloseHandle invalid handle",
                            location, "Calls CloseHandle with 0/-1/-2 — generates exception only when debugger present", "Medium"));


                    if (src.Contains("Marshal.GetExceptionCode"))
                        findings.Add(new AntiDebugFinding("Exception", "Marshal.GetExceptionCode",
                            location, "Uses structured exception handling via Marshal.GetExceptionCode", "Low"));
                }
                catch { continue; }
            }
        }

        return findings;
    }

    private static List<AntiDebugFinding> ScanTLSCallbacks(ICSharpCode.Decompiler.Metadata.PEFile peFile)
    {
        var findings = new List<AntiDebugFinding>();
        try
        {
            var tlsDir = peFile.Reader.PEHeaders.PEHeader?.ThreadLocalStorageTableDirectory;
            if (tlsDir.HasValue && tlsDir.Value.RelativeVirtualAddress != 0)
            {
                findings.Add(new AntiDebugFinding(
                    "TLSCallback",
                    "TLS Callbacks Present",
                    "Assembly-level (PE Header)",
                    $"TLS directory RVA=0x{tlsDir.Value.RelativeVirtualAddress:X} — code may execute before Main entry point",
                    "High"));
            }
        }
        catch { }
        return findings;
    }

    private static List<AntiDebugFinding> ScanHardwareBreakpointDetection(ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler)
    {
        var findings = new List<AntiDebugFinding>();

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                try
                {
                    var src = decompiler.DecompileAsString(method.MetadataToken);
                    var location = $"{type.FullName}.{method.Name}";


                    if (Regex.IsMatch(src, @"0x10|CONTEXT_DEBUG_REGISTERS") &&
                        (src.Contains("GetThreadContext") || src.Contains("NtGetContextThread")))
                        findings.Add(new AntiDebugFinding("HardwareBreakpoint", "Hardware Breakpoint Detection via CONTEXT",
                            location, "Reads thread context with CONTEXT_DEBUG_REGISTERS flag to check Dr0-Dr3", "High"));


                    if (Regex.IsMatch(src, @"\bDr[0-7]\b") && src.Contains("context", StringComparison.OrdinalIgnoreCase))
                        findings.Add(new AntiDebugFinding("HardwareBreakpoint", "Hardware Breakpoint Register Read",
                            location, "Directly references debug registers Dr0-Dr7 — hardware breakpoint detection", "High"));


                    if (src.Contains("NtSetInformationThread") &&
                        Regex.IsMatch(src, @"\b17\b|0x11\b|ThreadHideFromDebugger"))
                        findings.Add(new AntiDebugFinding("ThreadHiding", "ThreadHideFromDebugger",
                            location, "Calls NtSetInformationThread with ThreadHideFromDebugger (0x11) — hides thread from debugger", "High"));
                }
                catch { continue; }
            }
        }

        return findings;
    }
}
