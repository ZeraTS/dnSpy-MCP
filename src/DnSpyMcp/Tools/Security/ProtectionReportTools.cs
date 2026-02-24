using System.ComponentModel;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using DnSpyMcp.Core;
using DnSpyMcp.Models;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Security;

[McpServerToolType]
public class ProtectionReportTools
{
    private readonly AssemblyCache _cache;
    private readonly AntiDebugTools _antiDebug;
    private readonly AntiTamperTools _antiTamper;

    public ProtectionReportTools(AssemblyCache cache)
    {
        _cache = cache;
        _antiDebug = new AntiDebugTools(cache);
        _antiTamper = new AntiTamperTools(cache);
    }

    [McpServerTool(Name = "get_protection_report"), Description("Aggregate anti-debug + anti-tamper analysis into a comprehensive protection report with risk score (0-10) and bypass recommendations")]
    public ProtectionReport GetProtectionReport(
        [Description("Absolute or relative path to the .NET assembly to analyse")] string assemblyPath)
    {
        try
        {
            var antiDebugFindings = _antiDebug.DetectAntiDebug(assemblyPath);
            var antiTamperFindings = _antiTamper.DetectAntiTamper(assemblyPath);


            var score = Math.Min(10.0,
                antiDebugFindings.Count(f => f.Severity == "High") * 1.5 +
                antiDebugFindings.Count(f => f.Severity == "Medium") * 0.75 +
                antiDebugFindings.Count(f => f.Severity == "Low") * 0.25 +
                antiTamperFindings.Count(f => f.Confidence == "High") * 1.5 +
                antiTamperFindings.Count(f => f.Confidence == "Medium") * 0.75 +
                antiTamperFindings.Count(f => f.Confidence == "Low") * 0.25
            );


            var summary = new List<string>();
            if (antiDebugFindings.Any(f => f.Category != "Error"))
                summary.Add($"{antiDebugFindings.Count} anti-debug technique(s) detected: {string.Join(", ", antiDebugFindings.Select(f => f.Technique).Distinct())}");
            if (antiTamperFindings.Any(f => f.Category != "Error"))
                summary.Add($"{antiTamperFindings.Count} anti-tamper/protection indicator(s): {string.Join(", ", antiTamperFindings.Select(f => f.Technique).Distinct())}");


            var bypasses = new List<string>();
            var allTechniques = antiDebugFindings.Select(f => f.Technique)
                .Concat(antiTamperFindings.Select(f => f.Technique))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (allTechniques.Any(t => t.Contains("IsDebuggerPresent") || t.Contains("CheckRemote")))
                bypasses.Add("Patch IsDebuggerPresent return value to 0 (NOP the check or use ScyllaHide)");
            if (allTechniques.Any(t => t.Contains("NtQueryInformationProcess")))
                bypasses.Add("Hook NtQueryInformationProcess to return 0 for ProcessDebugPort and ProcessDebugFlags");
            if (allTechniques.Any(t => t.Contains("ThreadHideFromDebugger") || t.Contains("NtSetInformationThread")))
                bypasses.Add("Hook NtSetInformationThread and ignore ThreadHideFromDebugger (0x11) calls");
            if (allTechniques.Any(t => t.Contains("TLS")))
                bypasses.Add("Set a breakpoint on TLS callback address before EP; or use TLS-aware debugger option");
            if (allTechniques.Any(t => t.Contains("Timing") || t.Contains("TickCount") || t.Contains("Stopwatch") || t.Contains("DateTime")))
                bypasses.Add("Use TimeOut plugin or freeze RDTSC/GetTickCount to return constant value");
            if (allTechniques.Any(t => t.Contains("Hardware Breakpoint") || t.Contains("GetThreadContext") || t.Contains("CONTEXT")))
                bypasses.Add("Use software breakpoints (INT3) instead of hardware breakpoints; or hook GetThreadContext to zero Dr0-Dr3");
            if (allTechniques.Any(t => t.Contains("ConfuserEx") || t.Contains("Confuser")))
                bypasses.Add("Use de4dot with ConfuserEx plugin, or NoFuserEx for newer variants");
            if (allTechniques.Any(t => t.Contains("Eaz")))
                bypasses.Add("Use eazdevirt for Eazfuscator VM devirtualisation");
            if (allTechniques.Any(t => t.Contains("KoiVM")))
                bypasses.Add("Use OldRod devirtualizer for KoiVM; set breakpoints on dispatcher method");
            if (allTechniques.Any(t => t.Contains("String") && t.Contains("Encrypt", StringComparison.OrdinalIgnoreCase)))
                bypasses.Add("Use de4dot string decryption, or attach debugger after cctor runs to dump decrypted strings");
            if (allTechniques.Any(t => t.Contains("Integrity") || t.Contains("Self-hash") || t.Contains("Self-Integrity")))
                bypasses.Add("Patch integrity check branch (flip je/jne after hash comparison) or provide unmodified binary");
            if (allTechniques.Any(t => t.Contains("NtSetInformationThread") || t.Contains("ThreadHide")))
                bypasses.Add("Use x64dbg with ScyllaHide plugin — covers most Windows anti-debug techniques");
            if (allTechniques.Any(t => t.Contains("MPRESS") || t.Contains("UPX") || t.Contains("Packer") || t.Contains("Packed")))
                bypasses.Add("Unpack/dump the assembly first (e.g. UPX -d for UPX, or use ExtremeDumper for .NET)");
            if (allTechniques.Any(t => t.Contains("VM Dispatcher") || t.Contains("VirtualMachine")))
                bypasses.Add("Identify and patch VM dispatcher; use devirtualization tools for known VMs");
            if (allTechniques.Any(t => t.Contains("Dotfuscator")))
                bypasses.Add("Use de4dot for Dotfuscator deobfuscation");
            if (allTechniques.Any(t => t.Contains(".NET Reactor")))
                bypasses.Add("Use .NET Reactor deobfuscators or de4dot with NET_Reactor support");


            string assemblyName = GetAssemblyName(assemblyPath);

            return new ProtectionReport
            {
                AssemblyPath = assemblyPath,
                AssemblyName = assemblyName,
                RiskScore = (int)Math.Round(score),
                Summary = summary,
                AntiDebugFindings = antiDebugFindings,
                AntiTamperFindings = antiTamperFindings,
                RecommendedBypasses = bypasses.Distinct().ToList(),
                AnalysedAt = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            return new ProtectionReport
            {
                AssemblyPath = assemblyPath,
                AssemblyName = Path.GetFileName(assemblyPath),
                RiskScore = 0,
                Summary = [$"Analysis failed: {ex.Message}"],
                AnalysedAt = DateTime.UtcNow
            };
        }
    }

    private static string GetAssemblyName(string assemblyPath)
    {
        try
        {
            var abs = Path.GetFullPath(assemblyPath);
            using var stream = File.OpenRead(abs);
            using var pe = new PEReader(stream);
            if (!pe.HasMetadata) return Path.GetFileName(assemblyPath);
            var meta = pe.GetMetadataReader();
            var asm = meta.GetAssemblyDefinition();
            return meta.GetString(asm.Name);
        }
        catch
        {
            return Path.GetFileName(assemblyPath);
        }
    }
}
