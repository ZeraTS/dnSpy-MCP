using System.ComponentModel;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text.RegularExpressions;
using DnSpyMcp.Core;
using DnSpyMcp.Models;
using ICSharpCode.Decompiler.TypeSystem;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Security;

[McpServerToolType]
public class AntiTamperTools
{
    private readonly AssemblyCache _cache;

    public AntiTamperTools(AssemblyCache cache)
    {
        _cache = cache;
    }

    [McpServerTool(Name = "detect_anti_tamper"), Description("Static analysis to detect anti-tamper/obfuscation: obfuscator fingerprinting, string encryption stubs, control flow obfuscation, integrity checks, VM/packing indicators")]
    public List<AntiTamperFinding> DetectAntiTamper(
        [Description("Absolute or relative path to the .NET assembly to analyse")] string assemblyPath)
    {
        var findings = new List<AntiTamperFinding>();
        try
        {
            var (decompiler, peFile) = _cache.GetOrLoad(assemblyPath);


            findings.AddRange(FingerprintObfuscators(decompiler, peFile));


            findings.AddRange(DetectNameObfuscation(decompiler));


            findings.AddRange(DetectStringEncryptionFast(decompiler));


            findings.AddRange(DetectPacking(peFile));



            findings.AddRange(SinglePassMethodAnalysis(decompiler, budgetMs: 20_000));
        }
        catch (Exception ex)
        {
            findings.Add(new AntiTamperFinding("Error", "AnalysisError", ex.Message, "Assembly-level", "Low"));
        }

        return findings
            .GroupBy(f => f.Technique + "|" + f.Location)
            .Select(g => g.First())
            .ToList();
    }



    private static List<AntiTamperFinding> SinglePassMethodAnalysis(
        ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler,
        int budgetMs = 20_000)
    {
        var findings = new List<AntiTamperFinding>();
        var sw = Stopwatch.StartNew();
        int analysed = 0;

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            if (sw.ElapsedMilliseconds > budgetMs) break;

            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                if (sw.ElapsedMilliseconds > budgetMs) break;

                string src;
                try
                {
                    src = decompiler.DecompileAsString(method.MetadataToken);
                    analysed++;
                }
                catch { continue; }

                var location = $"{type.FullName}.{method.Name}";
                var lines = src.Split('\n');
                int lineCount = lines.Length;


                if (lineCount >= 5)
                {
                    int gotoCount  = Regex.Matches(src, @"\bgoto\b").Count;
                    int ifCount    = Regex.Matches(src, @"\bif\b\s*\(").Count;
                    int switchCount= Regex.Matches(src, @"\bswitch\b\s*\(").Count;
                    double branchDensity = (double)(gotoCount + ifCount + switchCount) / lineCount;

                    if (gotoCount > 5 && branchDensity > 0.33)
                        findings.Add(new AntiTamperFinding(
                            "ControlFlowObfuscation", "Control Flow Obfuscation",
                            $"Branch density {branchDensity:F2} ({gotoCount} gotos, {ifCount} ifs, {switchCount} switches in {lineCount} lines)",
                            location, "Medium"));

                    var caseMatches = Regex.Matches(src, @"\bcase\b");
                    if (caseMatches.Count > 50)
                        findings.Add(new AntiTamperFinding(
                            "VirtualMachine", "Custom VM Dispatcher",
                            $"Method has {caseMatches.Count} switch cases — possible VM opcode dispatcher",
                            location, "High"));
                    else if (caseMatches.Count > 5)
                    {
                        int realLines = lines.Count(l => !Regex.IsMatch(l.Trim(), @"^(case|break|goto|{|}|switch)"));
                        if (realLines < 5)
                            findings.Add(new AntiTamperFinding(
                                "ControlFlowObfuscation", "Switch-Based Control Flow Proxy",
                                $"{caseMatches.Count} switch cases with minimal real logic",
                                location, "Medium"));
                    }
                }


                bool hasCrypto      = src.Contains("MD5") || src.Contains("SHA256") || src.Contains("SHA1") || src.Contains("SHA512");
                bool hasAssemblyRef = src.Contains("GetExecutingAssembly") || src.Contains("MainModule");
                bool hasFileRead    = src.Contains("File.ReadAllBytes") && (src.Contains("Assembly.Location") || src.Contains("GetExecutingAssembly"));
                bool hasTermination = Regex.IsMatch(src, @"Environment\.Exit\s*\(|Process\.Kill\s*\(|Process\.GetCurrentProcess\s*\(\s*\)\.Kill");
                bool hasPointerRead = src.Contains("Marshal.ReadInt32") || src.Contains("Marshal.ReadByte");

                if (hasCrypto && (hasAssemblyRef || hasPointerRead))
                    findings.Add(new AntiTamperFinding(
                        "IntegrityCheck", "Self-Integrity Hash Check",
                        "Cryptographic hash of own assembly/memory detected",
                        location, "High"));

                if (hasFileRead)
                    findings.Add(new AntiTamperFinding(
                        "IntegrityCheck", "File-Based Integrity Check",
                        "Reads own assembly via File.ReadAllBytes + Assembly.Location",
                        location, "High"));

                if (hasTermination && hasCrypto)
                    findings.Add(new AntiTamperFinding(
                        "IntegrityCheck", "Integrity Enforcement (Terminate on Tamper)",
                        "Process termination after hash comparison",
                        location, "High"));


                if (src.Contains("GetDelegateForFunctionPointer"))
                    findings.Add(new AntiTamperFinding(
                        "VirtualMachine", "Dynamic Native Invocation",
                        "Marshal.GetDelegateForFunctionPointer — dynamic native code invocation",
                        location, "Medium"));

                if (Regex.IsMatch(src, @"unsafe|fixed\s*\(") &&
                    src.Contains("Marshal") &&
                    Regex.IsMatch(src, @"new byte\[\s*\d+\s*\]"))
                    findings.Add(new AntiTamperFinding(
                        "VirtualMachine", "Encrypted IL Stub",
                        "Unsafe block with byte array + Marshal — possible encrypted IL or shellcode",
                        location, "Medium"));
            }
        }

        return findings;
    }



    private static List<AntiTamperFinding> FingerprintObfuscators(
        ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler,
        ICSharpCode.Decompiler.Metadata.PEFile peFile)
    {
        var findings = new List<AntiTamperFinding>();

        var allTypeNames    = new List<string>();
        var allNamespaces   = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allAttrNames    = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            try
            {
                allTypeNames.Add(type.FullName);
                if (!string.IsNullOrEmpty(type.Namespace)) allNamespaces.Add(type.Namespace);
                foreach (var attr in type.GetAttributes()) allAttrNames.Add(attr.AttributeType.Name);
            }
            catch { }
        }
        try
        {
            foreach (var attr in decompiler.TypeSystem.MainModule.GetAssemblyAttributes())
            {
                try { allAttrNames.Add(attr.AttributeType.Name); } catch { }
            }
        }
        catch { }

        var sectionNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var sec in peFile.Reader.PEHeaders.SectionHeaders)
                sectionNames.Add(sec.Name.TrimEnd('\0'));
        }
        catch { }

        var checks = new List<(string Name, Func<bool> Check, string Evidence, string Confidence)>
        {
            ("ConfuserEx",
                () => allAttrNames.Any(a => a.Contains("ConfusedBy", StringComparison.OrdinalIgnoreCase))
                   || allTypeNames.Any(t => t.Contains("Confuser", StringComparison.OrdinalIgnoreCase)),
                "ConfusedByAttribute or Confuser type/namespace found", "High"),

            ("Dotfuscator",
                () => allAttrNames.Any(a => a.Contains("Dotfuscator", StringComparison.OrdinalIgnoreCase))
                   || allNamespaces.Any(n => n.StartsWith("PreEmptive.Dotfuscator", StringComparison.OrdinalIgnoreCase)),
                "DotfuscatorAttribute or PreEmptive.Dotfuscator namespace", "High"),

            ("Eazfuscator",
                () => allAttrNames.Any(a => a.Contains("Obfuscation", StringComparison.OrdinalIgnoreCase))
                   || allTypeNames.Any(t => t.Any(c => c >= '\u0001' && c <= '\u001F')),
                "ObfuscationAttribute or control-char type names", "High"),

            (".NET Reactor",
                () => sectionNames.Any(s => s.Contains("dotNetProtector", StringComparison.OrdinalIgnoreCase))
                   || allAttrNames.Any(a => a.Contains("NetReactor", StringComparison.OrdinalIgnoreCase)),
                "dotNetProtector PE section or NetReactor attribute", "High"),

            ("SmartAssembly",
                () => allNamespaces.Any(n => n.StartsWith("SmartAssembly.Attributes", StringComparison.OrdinalIgnoreCase))
                   || allAttrNames.Any(a => a.Equals("ObfuscatedAttribute", StringComparison.OrdinalIgnoreCase)),
                "SmartAssembly.Attributes namespace or [Obfuscated] attribute", "High"),

            ("Babel Obfuscator",
                () => allNamespaces.Any(n => n.StartsWith("Babel.Obfuscator", StringComparison.OrdinalIgnoreCase))
                   || allAttrNames.Any(a => a.Contains("Babel", StringComparison.OrdinalIgnoreCase)),
                "Babel.Obfuscator namespace or attribute", "High"),

            ("DeepSea Obfuscator",
                () => allNamespaces.Any(n => n.StartsWith("DeepSea.Obfuscator", StringComparison.OrdinalIgnoreCase)
                                          || n.StartsWith("SeaSharp", StringComparison.OrdinalIgnoreCase)),
                "DeepSea.Obfuscator or SeaSharp namespace", "High"),

            ("Crypto Obfuscator",
                () => allNamespaces.Any(n => n.StartsWith("Crypto.Obfuscator", StringComparison.OrdinalIgnoreCase))
                   || allAttrNames.Any(a => a.Contains("CryptoObfuscator", StringComparison.OrdinalIgnoreCase)),
                "Crypto.Obfuscator namespace or CryptoObfuscator attribute", "High"),

            ("Xenocode/PostBuild",
                () => allNamespaces.Any(n => n.StartsWith("Xenocode.Client.Attributes", StringComparison.OrdinalIgnoreCase))
                   || allAttrNames.Any(a => a.Contains("PostBuild", StringComparison.OrdinalIgnoreCase)),
                "Xenocode.Client.Attributes namespace or PostBuild attribute", "Medium"),

            ("KoiVM",
                () => allNamespaces.Any(n => n.StartsWith("KoiVM.Runtime", StringComparison.OrdinalIgnoreCase))
                   || allTypeNames.Any(t => t.Contains("KoiVM", StringComparison.OrdinalIgnoreCase)),
                "KoiVM.Runtime namespace or KoiVM type names", "High"),

            ("Agile.NET",
                () => allNamespaces.Any(n => n.StartsWith("Agile.NET", StringComparison.OrdinalIgnoreCase)
                                          || n.StartsWith("CliSecure", StringComparison.OrdinalIgnoreCase))
                   || allAttrNames.Any(a => a.Contains("CliSecure", StringComparison.OrdinalIgnoreCase)),
                "Agile.NET or CliSecure namespace/attribute", "High"),

            ("MPRESS",
                () => sectionNames.Contains("MPRESS1") || sectionNames.Contains("MPRESS2"),
                "MPRESS1/MPRESS2 PE section names", "High"),

            ("Obfuscar",
                () => allAttrNames.Any(a => a.Contains("Obfuscar", StringComparison.OrdinalIgnoreCase)),
                "Obfuscar attribute", "Medium"),

            ("Goliath.NET",
                () => allNamespaces.Any(n => n.StartsWith("Goliath.Obfuscator", StringComparison.OrdinalIgnoreCase)),
                "Goliath.Obfuscator namespace", "High"),
        };

        foreach (var (name, check, evidence, confidence) in checks)
        {
            try { if (check()) findings.Add(new AntiTamperFinding("Obfuscator", name, evidence, "Assembly-level", confidence)); }
            catch { }
        }

        return findings;
    }



    private static List<AntiTamperFinding> DetectNameObfuscation(
        ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler)
    {
        var findings = new List<AntiTamperFinding>();
        int total = 0, obfuscated = 0;
        bool hasZeroWidth = false;

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            try
            {
                total++; if (IsObfuscatedName(type.Name)) obfuscated++;
                if (HasZeroWidthChars(type.Name)) hasZeroWidth = true;
                foreach (var m in type.Methods)   { total++; if (IsObfuscatedName(m.Name)) obfuscated++; if (HasZeroWidthChars(m.Name)) hasZeroWidth = true; }
                foreach (var f in type.Fields)    { total++; if (IsObfuscatedName(f.Name)) obfuscated++; if (HasZeroWidthChars(f.Name)) hasZeroWidth = true; }
                foreach (var p in type.Properties){ total++; if (IsObfuscatedName(p.Name)) obfuscated++; if (HasZeroWidthChars(p.Name)) hasZeroWidth = true; }
            }
            catch { }
        }

        if (hasZeroWidth)
            findings.Add(new AntiTamperFinding("NameObfuscation", "Homoglyph/Invisible Name Obfuscation",
                "Zero-width chars (U+200B/U+200C/U+200D/U+FEFF) in member names", "Assembly-level", "High"));

        if (total > 0 && (double)obfuscated / total > 0.30)
            findings.Add(new AntiTamperFinding("NameObfuscation", "Heavy Name Obfuscation",
                $"{obfuscated}/{total} members ({100 * obfuscated / total}%) have obfuscated names",
                "Assembly-level", "Medium"));

        return findings;
    }



    private static List<AntiTamperFinding> DetectStringEncryptionFast(
        ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler)
    {
        var findings = new List<AntiTamperFinding>();

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            try
            {

                var cctor = type.Methods.FirstOrDefault(m => m.Name == ".cctor");
                if (cctor?.HasBody == true)
                {
                    try
                    {
                        var src = decompiler.DecompileAsString(cctor.MetadataToken);
                        bool hasArrayAlloc  = src.Contains("new byte[") || src.Contains("new char[") || src.Contains("new string[");
                        bool hasStringLits  = Regex.IsMatch(src, "\"[A-Za-z ]{3,}\"");
                        bool hasLoopFilling = Regex.IsMatch(src, @"\[[\w\d]+\]\s*=");
                        if (hasArrayAlloc && hasLoopFilling && !hasStringLits)
                            findings.Add(new AntiTamperFinding("StringEncryption", "String Array Encryption Stub",
                                "Static constructor fills array without readable strings",
                                $"{type.FullName}..cctor", "High"));
                    }
                    catch { }
                }


                foreach (var m in type.Methods)
                {
                    try
                    {
                        if (m.ReturnType.FullName == "System.String" &&
                            m.Parameters.Count == 1 &&
                            (m.Parameters[0].Type.FullName == "System.Int32" ||
                             m.Parameters[0].Type.FullName == "System.Byte[]") &&
                            IsObfuscatedName(m.Name))
                            findings.Add(new AntiTamperFinding("StringEncryption", "String Decryption Method",
                                "Obfuscated-name method: (int|byte[]) → string",
                                $"{type.FullName}.{m.Name}", "High"));
                    }
                    catch { }
                }
            }
            catch { }
        }

        return findings;
    }



    private static List<AntiTamperFinding> DetectPacking(ICSharpCode.Decompiler.Metadata.PEFile peFile)
    {
        var findings = new List<AntiTamperFinding>();
        try
        {
            var packers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "UPX0","UPX1","MPRESS1","MPRESS2",".netshrink",
                "Themida","WinLicense",".vmp0",".vmp1",".vmp2",
                "dotNetProtector",".enigma1",".enigma2"
            };
            var headers  = peFile.Reader.PEHeaders;
            var sections = headers.SectionHeaders.ToList();

            foreach (var sec in sections)
            {
                var name = sec.Name.TrimEnd('\0');
                if (packers.Contains(name))
                    findings.Add(new AntiTamperFinding("Packing", $"Packer Section: {name}",
                        $"PE section '{name}' is a known packer/protector signature",
                        $"PE Section: {name}", "High"));
            }

            var epRva = headers.PEHeader?.AddressOfEntryPoint ?? 0;
            if (epRva != 0)
            {
                var epSec = sections.FirstOrDefault(s => epRva >= s.VirtualAddress && epRva < s.VirtualAddress + s.VirtualSize);
                var epName = epSec.Name.TrimEnd('\0');
                if (!string.IsNullOrEmpty(epName) &&
                    !epName.Equals(".text", StringComparison.OrdinalIgnoreCase) &&
                    !epName.Equals("CODE",  StringComparison.OrdinalIgnoreCase))
                    findings.Add(new AntiTamperFinding("Packing", "Entry Point in Non-Standard Section",
                        $"EP RVA 0x{epRva:X} is in section '{epName}' (expected .text) — possible packing",
                        $"PE Entry Point (section {epName})", "High"));
            }
        }
        catch { }
        return findings;
    }



    private static bool IsObfuscatedName(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (name.Any(c => c >= '\u0001' && c <= '\u001F')) return true;
        if (name.Contains('<') || name.Contains('>')) return true;
        if (name.Length == 1 && char.IsLetter(name[0])) return true;
        if (name.All(char.IsDigit)) return true;
        return false;
    }

    private static bool HasZeroWidthChars(string name) =>
        name.Any(c => c == '\u200B' || c == '\u200C' || c == '\u200D' || c == '\uFEFF');
}
