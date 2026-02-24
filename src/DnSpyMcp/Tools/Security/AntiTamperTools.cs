using System.ComponentModel;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Collections.Immutable;
using System.Text;
using DnSpyMcp.Core;
using DnSpyMcp.Models;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Security;

[McpServerToolType]
public class AntiTamperTools
{
    private readonly AssemblyCache _cache;
    public AntiTamperTools(AssemblyCache cache) { _cache = cache; }

    [McpServerTool(Name = "detect_anti_tamper"), Description("Fast static detection of anti-tamper and obfuscation via raw binary byte search, PE header inspection, metadata table scanning, and IL opcode analysis. No decompilation — fingerprints 20+ protectors and detects string encryption, control flow obfuscation, packing, VM dispatchers, and integrity checks. Completes in milliseconds.")]
    public List<AntiTamperFinding> DetectAntiTamper(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath)
    {
        var findings = new List<AntiTamperFinding>();
        try
        {
            var abs = Path.GetFullPath(assemblyPath);
            if (!File.Exists(abs)) throw new FileNotFoundException($"Not found: {abs}");

            var (_, peFile) = _cache.GetOrLoad(assemblyPath);
            var raw = File.ReadAllBytes(abs);
            var peHeaders = peFile.Reader.PEHeaders;
            var sections = peHeaders.SectionHeaders.ToList();

            findings.AddRange(FingerprintObfuscators(raw, sections));
            findings.AddRange(ScanNameObfuscation(raw, peFile));
            findings.AddRange(DetectStringEncryption(raw, peFile));
            findings.AddRange(DetectControlFlow(peFile));
            findings.AddRange(DetectIntegrityChecks(raw));
            findings.AddRange(DetectPacking(raw, sections, peHeaders));
        }
        catch (Exception ex)
        {
            findings.Add(new AntiTamperFinding("Error", "AnalysisError", ex.Message, "Assembly-level", "Low"));
        }

        return findings
            .GroupBy(f => f.Technique + "|" + f.Location)
            .Select(g => g.First())
            .OrderBy(f => f.Category)
            .ToList();
    }

    private static List<AntiTamperFinding> FingerprintObfuscators(byte[] raw, IReadOnlyList<SectionHeader> sections)
    {
        var findings = new List<AntiTamperFinding>();
        var sectionNames = new HashSet<string>(sections.Select(s => s.Name.TrimEnd('\0')), StringComparer.OrdinalIgnoreCase);

        bool Has(string s) => ContainsUtf8(raw, s);
        bool HasW(string s) => ContainsUtf16LE(raw, s);
        bool HasSection(string s) => sectionNames.Contains(s);

        var checks = new (string Name, Func<bool> Check, string Evidence, string Confidence)[]
        {
            ("ConfuserEx",
                () => Has("ConfusedByAttribute") || Has("ConfuserEx v") || HasW("вє∂ѕ ρяσтє¢тσя"),
                "ConfusedByAttribute or ConfuserEx version string in binary",
                "High"),

            ("ConfuserEx (DotNetPatcher mod)",
                () => Has("ConfusedByAttribute") && Has("DotNetPatcherPackerAttribute"),
                "ConfusedByAttribute + DotNetPatcherPackerAttribute",
                "High"),

            ("Dotfuscator",
                () => Has("DotfuscatorAttribute") || Has("PreEmptive.Dotfuscator"),
                "DotfuscatorAttribute or PreEmptive.Dotfuscator namespace in binary",
                "High"),

            ("Eazfuscator",
                () => Has("EazFuscator") || Has("Gapotchenko") || Has("eazfuscator"),
                "EazFuscator string in binary",
                "High"),

            (".NET Reactor",
                () => HasSection(".reacto") || Has("m_isReadOnly") || Has("NecroVM.Runtime") ||
                      (Has("BinaryReader") && Has("RSACryptoServiceProvider") && HasW(" is tampered.")),
                ".reacto section, NecroVM.Runtime namespace, m_isReadOnly marker, or anti-tamper message string",
                "High"),

            ("SmartAssembly",
                () => Has("SmartAssembly") || Has("ObfuscatedAttribute") || Has("SmartAssembly.Attributes"),
                "SmartAssembly namespace or ObfuscatedAttribute in binary",
                "High"),

            ("Babel Obfuscator",
                () => Has("Babel.Obfuscator"),
                "Babel.Obfuscator namespace in binary",
                "High"),

            ("DeepSea Obfuscator",
                () => Has("DeepSea.Obfuscator") || Has("SeaSharp"),
                "DeepSea.Obfuscator or SeaSharp namespace in binary",
                "High"),

            ("Crypto Obfuscator",
                () => Has("CryptoObfuscator") || Has("Crypto.Obfuscator"),
                "CryptoObfuscator attribute or Crypto.Obfuscator namespace in binary",
                "High"),

            ("Agile.NET / CliSecure",
                () => Has("Agile.NET") || Has("CliSecure"),
                "Agile.NET or CliSecure namespace/attribute in binary",
                "High"),

            ("KoiVM",
                () => Has("KoiVM") || Has("VMEntryRun"),
                "KoiVM or VMEntryRun string in binary",
                "High"),

            ("VMProtect .NET",
                () => Has("SuppressIldasmAttribute") && Has("get_IsAttached") && Has("OpCodes"),
                "VMProtect triple signature: SuppressIldasmAttribute + get_IsAttached + OpCodes",
                "High"),

            ("Goliath.NET",
                () => Has("Goliath.Obfuscator"),
                "Goliath.Obfuscator namespace in binary",
                "High"),

            ("Xenocode/PostBuild",
                () => Has("Xenocode.Client") || Has("PostBuild"),
                "Xenocode.Client namespace or PostBuild attribute in binary",
                "Medium"),

            ("Obfuscar",
                () => Has("Obfuscar"),
                "Obfuscar string in binary",
                "Medium"),

            ("SuppressIldasmAttribute",
                () => Has("SuppressIldasmAttribute") && !Has("System.Runtime"),
                "SuppressIldasmAttribute — prevents ILDASM from opening the assembly",
                "Low"),

            ("NecroVM / Custom VM",
                () => Has("NecroVM"),
                "NecroVM runtime strings — custom .NET VM protector",
                "High"),
        };

        foreach (var (name, check, evidence, confidence) in checks)
        {
            try
            {
                if (check())
                    findings.Add(new AntiTamperFinding("Obfuscator", name, evidence, "Assembly-level", confidence));
            }
            catch { }
        }

        return findings;
    }

    private static List<AntiTamperFinding> ScanNameObfuscation(byte[] raw, ICSharpCode.Decompiler.Metadata.PEFile peFile)
    {
        var findings = new List<AntiTamperFinding>();
        try
        {
            var meta = peFile.Metadata;
            int total = 0, obfuscated = 0;
            bool hasZeroWidth = false;

            foreach (var tdh in meta.TypeDefinitions)
            {
                var td = meta.GetTypeDefinition(tdh);
                var typeName = meta.GetString(td.Name);
                total++;
                if (IsObfuscatedName(typeName)) obfuscated++;
                if (HasZeroWidthChars(typeName)) hasZeroWidth = true;

                foreach (var mh in td.GetMethods())
                {
                    var name = meta.GetString(meta.GetMethodDefinition(mh).Name);
                    total++;
                    if (IsObfuscatedName(name)) obfuscated++;
                    if (HasZeroWidthChars(name)) hasZeroWidth = true;
                }
                foreach (var fh in td.GetFields())
                {
                    var name = meta.GetString(meta.GetFieldDefinition(fh).Name);
                    total++;
                    if (IsObfuscatedName(name)) obfuscated++;
                    if (HasZeroWidthChars(name)) hasZeroWidth = true;
                }
            }

            if (hasZeroWidth)
                findings.Add(new AntiTamperFinding("NameObfuscation", "Zero-Width Character Names",
                    "Zero-width chars (U+200B/U+200C/U+200D/U+FEFF) in member names — homoglyph obfuscation",
                    "Assembly-level", "High"));

            if (total >= 20 && (double)obfuscated / total > 0.30)
                findings.Add(new AntiTamperFinding("NameObfuscation", "Heavy Name Obfuscation",
                    $"{obfuscated}/{total} members ({100 * obfuscated / total}%) have obfuscated names (control chars, <>, single char, all-digit)",
                    "Assembly-level", "Medium"));
        }
        catch { }
        return findings;
    }

    private static List<AntiTamperFinding> DetectStringEncryption(byte[] raw, ICSharpCode.Decompiler.Metadata.PEFile peFile)
    {
        var findings = new List<AntiTamperFinding>();
        try
        {
            var meta = peFile.Metadata;

            int intToStringMethods = 0;
            int cctorCount = 0;

            foreach (var tdh in meta.TypeDefinitions)
            {
                var td = meta.GetTypeDefinition(tdh);
                foreach (var mh in td.GetMethods())
                {
                    var md = meta.GetMethodDefinition(mh);
                    var methodName = meta.GetString(md.Name);
                    var sig = md.DecodeSignature(new SimpleSignatureDecoder(meta), default);

                    if (IsObfuscatedName(methodName) &&
                        sig.ReturnType == "String" &&
                        sig.ParameterTypes.Length == 1 &&
                        (sig.ParameterTypes[0] == "Int32" || sig.ParameterTypes[0] == "Byte[]"))
                    {
                        intToStringMethods++;
                    }

                    if (methodName == ".cctor") cctorCount++;
                }
            }

            if (intToStringMethods > 0)
                findings.Add(new AntiTamperFinding("StringEncryption", "String Decryption Methods",
                    $"{intToStringMethods} method(s) with obfuscated name, signature (int|byte[]) → string — classic string decrypt stub pattern",
                    "Assembly-level", "High"));

        }
        catch { }
        return findings;
    }

    private static List<AntiTamperFinding> DetectControlFlow(ICSharpCode.Decompiler.Metadata.PEFile peFile)
    {
        var findings = new List<AntiTamperFinding>();
        try
        {
            var meta = peFile.Metadata;
            int hotMethods = 0;
            int vmDispatchers = 0;

            foreach (var tdh in meta.TypeDefinitions)
            {
                var td = meta.GetTypeDefinition(tdh);
                var typeName = meta.GetString(td.Name);

                foreach (var mh in td.GetMethods())
                {
                    var md = meta.GetMethodDefinition(mh);
                    if (md.RelativeVirtualAddress == 0) continue;
                    try
                    {
                        var body = peFile.Reader.GetMethodBody(md.RelativeVirtualAddress);
                        if (body.Size == 0) continue;
                        var il = body.GetILReader();
                        var ilBytes = il.ReadBytes(il.RemainingBytes);

                        int branches = 0, switches = 0, switchCases = 0;
                        AnalyseIL(ilBytes, ref branches, ref switches, ref switchCases);

                        int lineCount = Math.Max(1, ilBytes.Length / 4);
                        double density = (double)(branches + switches) / lineCount;

                        if (switchCases > 500)
                        {
                            vmDispatchers++;
                            if (vmDispatchers <= 3)
                            {
                                var methodName = meta.GetString(md.Name);
                                findings.Add(new AntiTamperFinding("VirtualMachine", "VM Opcode Dispatcher",
                                    $"{switchCases} switch cases in raw IL — VM opcode dispatch table",
                                    $"{typeName}.{methodName}", "High"));
                            }
                        }
                        else if (branches > 30 && density > 0.5)
                        {
                            hotMethods++;
                        }
                    }
                    catch { }
                }
            }

            if (hotMethods > 10)
                findings.Add(new AntiTamperFinding("ControlFlowObfuscation", "High Branch Density",
                    $"{hotMethods} methods with branch density > 40% in raw IL — control flow obfuscation pattern",
                    "Assembly-level", "Medium"));

            if (vmDispatchers > 3)
                findings.Add(new AntiTamperFinding("VirtualMachine", "Multiple VM Dispatchers",
                    $"{vmDispatchers} methods with >500 switch cases — consistent VM dispatcher pattern",
                    "Assembly-level", "High"));
        }
        catch { }
        return findings;
    }

    private static List<AntiTamperFinding> DetectIntegrityChecks(byte[] raw)
    {
        var findings = new List<AntiTamperFinding>();

        bool hasCrypto = ContainsUtf8(raw, "MD5") || ContainsUtf8(raw, "SHA256") ||
                          ContainsUtf8(raw, "SHA1") || ContainsUtf8(raw, "SHA512");
        bool hasAssemblyRef = ContainsUtf8(raw, "GetExecutingAssembly");
        bool hasFileRead = ContainsUtf8(raw, "ReadAllBytes");
        bool hasTamperMsg = ContainsUtf16LE(raw, " is tampered.") || ContainsUtf16LE(raw, "tampered") ||
                             ContainsUtf8(raw, "tampered");

        if (hasCrypto && hasAssemblyRef && hasFileRead)
            findings.Add(new AntiTamperFinding("IntegrityCheck", "Self-Integrity Hash Check",
                "Cryptographic hash API + GetExecutingAssembly + ReadAllBytes — reads and hashes own assembly",
                "Assembly-level", "High"));

        if (hasTamperMsg)
            findings.Add(new AntiTamperFinding("IntegrityCheck", "Anti-Tamper Message String",
                "String literal ' is tampered.' or 'tampered' in binary — integrity enforcement message",
                "Assembly-level", "High"));

        return findings;
    }

    private static List<AntiTamperFinding> DetectPacking(byte[] raw, IReadOnlyList<SectionHeader> sections, PEHeaders peHeaders)
    {
        var findings = new List<AntiTamperFinding>();
        try
        {
            var packers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "UPX0","UPX1","MPRESS1","MPRESS2",".netshrink","Themida",
                "WinLicense",".vmp0",".vmp1",".vmp2","dotNetProtector",
                ".enigma1",".enigma2",".reacto",".winlice",".themida"
            };

            foreach (var sec in sections)
            {
                var name = sec.Name.TrimEnd('\0');
                if (packers.Contains(name))
                    findings.Add(new AntiTamperFinding("Packing", $"Packer Section: {name}",
                        $"PE section '{name}' matches known packer/protector signature",
                        $"PE Section: {name}", "High"));

                var rawSize = Math.Min(sec.SizeOfRawData, raw.Length - sec.PointerToRawData);
                if (sec.PointerToRawData >= 0 && rawSize > 256)
                {
                    var sectionSpan = raw.AsSpan(sec.PointerToRawData, rawSize);
                    double entropy = CalcEntropy(sectionSpan);
                    if (entropy > 7.2 && name != ".rsrc")
                        findings.Add(new AntiTamperFinding("Packing", "High Entropy Section",
                            $"Section '{name}' entropy={entropy:F2}/8.0 — likely encrypted or compressed content",
                            $"PE Section: {name}", "Medium"));
                }
            }

            var epRva = peHeaders.PEHeader?.AddressOfEntryPoint ?? 0;
            if (epRva != 0)
            {
                var epSec = sections.FirstOrDefault(s =>
                    epRva >= s.VirtualAddress && epRva < s.VirtualAddress + s.VirtualSize);
                var epName = epSec.Name.TrimEnd('\0');
                if (!string.IsNullOrEmpty(epName) &&
                    !epName.Equals(".text", StringComparison.OrdinalIgnoreCase) &&
                    !epName.Equals("CODE", StringComparison.OrdinalIgnoreCase))
                    findings.Add(new AntiTamperFinding("Packing", "Entry Point in Non-Standard Section",
                        $"EP RVA 0x{epRva:X} is in section '{epName}' (expected .text) — packer stub",
                        $"PE Entry Point (section {epName})", "High"));
            }

            if (ContainsUtf8(raw, "UPX!"))
                findings.Add(new AntiTamperFinding("Packing", "UPX Signature",
                    "UPX! marker string in binary", "Binary", "High"));
        }
        catch { }
        return findings;
    }

    private static void AnalyseIL(byte[] il, ref int branches, ref int switches, ref int switchCases)
    {
        int i = 0;
        while (i < il.Length)
        {
            byte op = il[i++];
            switch (op)
            {
                case 0x45: 
                    switches++;
                    if (i + 4 <= il.Length)
                    {
                        uint n = BitConverter.ToUInt32(il, i);
                        if (n < 10000)
                        {
                            switchCases += (int)n;
                            i += 4 + (int)n * 4;
                        }
                        else { i += 4; }
                    }
                    break;
                case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C:
                case 0x3D: case 0x3E: case 0x3F: case 0x40: case 0x41:
                case 0x42: case 0x43: case 0x44:
                    branches++; i += 4; break;
                case 0x2B: case 0x2C: case 0x2D: case 0x2E: case 0x2F:
                case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
                case 0x35: case 0x36: case 0x37:
                    branches++; i += 1; break;
                case 0xFE: i++; break;
                case 0x20: case 0x22: case 0xD3: i += 4; break;
                case 0x21: i += 8; break;
                case 0x28: case 0x29: case 0x6F: case 0x73: case 0x74:
                case 0x75: case 0x70: case 0x27: case 0xA5: case 0xC2: i += 4; break;
                default: break;
            }
        }
    }

    private static double CalcEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> freq = stackalloc int[256];
        freq.Clear();
        foreach (var b in data) freq[b]++;
        double entropy = 0, len = data.Length;
        for (int i = 0; i < 256; i++)
            if (freq[i] > 0) { double p = freq[i] / len; entropy -= p * Math.Log2(p); }
        return entropy;
    }

    private static bool ContainsUtf8(byte[] data, string value)
    {
        var pattern = Encoding.UTF8.GetBytes(value);
        return data.AsSpan().IndexOf(pattern) >= 0;
    }

    private static bool ContainsUtf16LE(byte[] data, string value)
    {
        var pattern = Encoding.Unicode.GetBytes(value);
        return data.AsSpan().IndexOf(pattern) >= 0;
    }

    private static bool ContainsPattern(byte[] data, byte[] prefix, byte maxThird)
    {
        for (int i = 0; i <= data.Length - 3; i++)
            if (data[i] == prefix[0] && data[i+1] == prefix[1] && data[i+2] <= maxThird)
                return true;
        return false;
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
        name.Any(c => c is '\u200B' or '\u200C' or '\u200D' or '\uFEFF');
}

internal sealed class SimpleSignatureDecoder : ISignatureTypeProvider<string, object?>
{
    private readonly MetadataReader _meta;
    public SimpleSignatureDecoder(MetadataReader meta) { _meta = meta; }
    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode.ToString();
    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind)
        => _meta.GetString(_meta.GetTypeDefinition(handle).Name);
    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind)
        => _meta.GetString(_meta.GetTypeReference(handle).Name);
    public string GetSZArrayType(string elementType) => elementType + "[]";
    public string GetArrayType(string elementType, ArrayShape shape) => elementType + "[]";
    public string GetByReferenceType(string elementType) => elementType + "&";
    public string GetPointerType(string elementType) => elementType + "*";
    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => genericType;
    public string GetGenericMethodParameter(object? genericContext, int index) => "T";
    public string GetGenericTypeParameter(object? genericContext, int index) => "T";
    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;
    public string GetPinnedType(string elementType) => elementType;
    public string GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind)
        => "TypeSpec";
    public string GetFunctionPointerType(MethodSignature<string> signature) => "FunctionPointer";
}
