using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Disassembler;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;

namespace dnSpyMCP.AutomatedDebugger;

// ─── Result types ─────────────────────────────────────────────────────────────

public record TypeInfo(string FullName, string Namespace, string Kind, bool IsPublic, bool IsAbstract, bool IsSealed, List<string> Interfaces);
public record MethodSummary(string Name, string FullName, string ReturnType, bool IsPublic, bool IsStatic, bool IsAbstract, bool IsVirtual, List<string> Parameters);
public record FieldSummary(string Name, string Type, bool IsPublic, bool IsStatic, bool IsReadOnly);
public record PropertySummary(string Name, string Type, bool CanRead, bool CanWrite, bool IsPublic, bool IsStatic);
public record MemberSearchResult(string MemberKind, string FullName, string? Signature, string? DeclaringType);
public record StringSearchResult(string Value, string FoundInType, string FoundInMethod);
public record ResourceInfo(string Name, string ResourceType, long Offset);
public record PEInfo(string Architecture, bool Is64Bit, bool IsManaged, string TargetFramework, string AssemblyName, string AssemblyVersion, bool IsSigned, string RuntimeVersion, List<string> Sections, Dictionary<string, string> CustomAttributes);
public record MetadataTokenResult(string TokenHex, string TableName, int RowNumber, string? FullName, string? Details);

public class TypeDetailInfo
{
    public string? FullName { get; init; }
    public string? Namespace { get; init; }
    public string? BaseType { get; init; }
    public string? Kind { get; init; }
    public bool IsAbstract { get; init; }
    public bool IsSealed { get; init; }
    public bool IsInterface { get; init; }
    public bool IsPublic { get; init; }
    public List<FieldSummary> Fields { get; init; } = [];
    public List<MethodSummary> Methods { get; init; } = [];
    public List<PropertySummary> Properties { get; init; } = [];
    public List<string> Interfaces { get; init; } = [];
    public string? DecompiledSource { get; init; }
}

public class MethodDetailInfo
{
    public string? Name { get; init; }
    public string? FullName { get; init; }
    public string? ReturnType { get; init; }
    public bool IsPublic { get; init; }
    public bool IsStatic { get; init; }
    public bool IsAbstract { get; init; }
    public bool IsVirtual { get; init; }
    public List<Dictionary<string, object?>> Parameters { get; init; } = [];
    public string? DeclaringType { get; init; }
    public string? DecompiledSource { get; init; }
    public string? ILCode { get; init; }
}

// ─── Main Debugger class ──────────────────────────────────────────────────────

/// <summary>
/// Static analysis engine powered by ICSharpCode.Decompiler (dnSpyEx).
/// Never executes the target assembly.
/// </summary>
public class Debugger
{
    private readonly string _binaryPath;
    private CSharpDecompiler? _decompiler;
    private bool _loaded;

    public Debugger(string binaryPath)
    {
        if (!File.Exists(binaryPath))
            throw new FileNotFoundException($"Binary not found: {binaryPath}");
        _binaryPath = binaryPath;
    }

    public bool LoadAssembly()
    {
        try
        {
            _decompiler = new CSharpDecompiler(_binaryPath, new DecompilerSettings
            {
                ThrowOnAssemblyResolveErrors = false,
                RemoveDeadCode = false,
                ShowXmlDocumentation = true,
                LoadInMemory = false,
            });
            _loaded = true;
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to load assembly: {ex.Message}");
            return false;
        }
    }

    private void EnsureLoaded()
    {
        if (!_loaded || _decompiler == null)
            throw new InvalidOperationException("Assembly not loaded. Call LoadAssembly() first.");
    }

    // ── Type enumeration ──────────────────────────────────────────────────────

    public List<TypeInfo> GetAllTypes()
    {
        EnsureLoaded();
        return _decompiler!.TypeSystem.MainModule.TypeDefinitions
            .Select(t =>
            {
                try { return new TypeInfo(t.FullName, t.Namespace, GetKind(t), t.Accessibility == Accessibility.Public, t.IsAbstract, t.IsSealed, t.DirectBaseTypes.Where(b => b.Kind == TypeKind.Interface).Select(b => b.FullName).ToList()); }
                catch { return null; }
            })
            .Where(t => t != null).Cast<TypeInfo>()
            .OrderBy(t => t.FullName).ToList();
    }

    // ── Method search ─────────────────────────────────────────────────────────

    public List<MethodSummary> FindMethods(string? pattern = null)
    {
        EnsureLoaded();
        var results = new List<MethodSummary>();
        foreach (var type in _decompiler!.TypeSystem.MainModule.TypeDefinitions)
            foreach (var m in type.Methods)
            {
                try
                {
                    if (pattern != null && !m.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;
                    results.Add(new MethodSummary(m.Name, type.FullName + "." + m.Name, m.ReturnType.FullName, m.Accessibility == Accessibility.Public, m.IsStatic, m.IsAbstract, m.IsVirtual, m.Parameters.Select(p => p.Type.FullName + " " + p.Name).ToList()));
                }
                catch { continue; }
            }
        return results;
    }

    // ── Decompilation ─────────────────────────────────────────────────────────

    public string DecompileAssembly()
    {
        EnsureLoaded();
        try { return _decompiler!.DecompileWholeModuleAsString(); }
        catch (Exception ex) { return $"// Error: {ex.Message}"; }
    }

    public string DecompileType(string typeName)
    {
        EnsureLoaded();
        try { return _decompiler!.DecompileTypeAsString(new FullTypeName(typeName)); }
        catch (Exception ex) { return $"// Error decompiling {typeName}: {ex.Message}"; }
    }

    public string DecompileMethod(string typeName, string methodName)
    {
        EnsureLoaded();
        try
        {
            var type = FindType(typeName);
            var method = FindMethod(type, methodName);
            return _decompiler!.DecompileAsString(method.MetadataToken);
        }
        catch (Exception ex) { return $"// Error decompiling {typeName}.{methodName}: {ex.Message}"; }
    }

    // ── IL Disassembly ────────────────────────────────────────────────────────

    public string DumpIL(string? typeName = null, string? methodName = null)
    {
        var sb = new StringBuilder();
        var output = new PlainTextOutput(new StringWriter(sb));
        try
        {
            using var stream = File.OpenRead(_binaryPath);
            var module = new ICSharpCode.Decompiler.Metadata.PEFile(_binaryPath, stream, PEStreamOptions.Default);
            var dis = new ReflectionDisassembler(output, CancellationToken.None);
            if (typeName == null) { dis.WriteModuleContents(module); }
            else
            {
                var meta = module.Metadata;
                foreach (var th in meta.TypeDefinitions)
                {
                    var td = meta.GetTypeDefinition(th);
                    var ns = meta.GetString(td.Namespace);
                    var nm = meta.GetString(td.Name);
                    var fn = string.IsNullOrEmpty(ns) ? nm : $"{ns}.{nm}";
                    if (!fn.Contains(typeName, StringComparison.OrdinalIgnoreCase)) continue;
                    if (methodName == null) { dis.DisassembleType(module, th); }
                    else
                    {
                        foreach (var mh in td.GetMethods())
                        {
                            var md = meta.GetMethodDefinition(mh);
                            if (meta.GetString(md.Name).Equals(methodName, StringComparison.OrdinalIgnoreCase))
                            { dis.DisassembleMethod(module, mh); break; }
                        }
                    }
                    break;
                }
            }
        }
        catch (Exception ex) { sb.AppendLine($"// IL dump error: {ex.Message}"); }
        return sb.ToString();
    }

    // ── String search (via decompiler — finds all ldstr string literals) ────────

    public List<StringSearchResult> SearchStrings(string pattern, bool useRegex = false)
    {
        EnsureLoaded();
        var results = new List<StringSearchResult>();
        Func<string, bool> match = useRegex
            ? s => Regex.IsMatch(s, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
            : s => s.Contains(pattern, StringComparison.OrdinalIgnoreCase);

        // Regex to extract string literals from decompiled C# output
        // Handles escaped chars; won't match verbatim strings prefixed with @
        var strRegex = new Regex("\"((?:[^\"\\\\]|\\\\.)*)\"", RegexOptions.Compiled);

        foreach (var type in _decompiler!.TypeSystem.MainModule.TypeDefinitions)
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                try
                {
                    var src = _decompiler.DecompileAsString(method.MetadataToken);
                    foreach (System.Text.RegularExpressions.Match m in strRegex.Matches(src))
                    {
                        var val = m.Groups[1].Value;
                        if (!string.IsNullOrEmpty(val) && match(val))
                            results.Add(new StringSearchResult(val, type.FullName, method.Name));
                    }
                }
                catch { continue; }
            }
        }

        // Deduplicate (same value+type)
        return results
            .GroupBy(r => r.Value + "|" + r.FoundInType + "|" + r.FoundInMethod)
            .Select(g => g.First())
            .ToList();
    }

    // ── Member search ─────────────────────────────────────────────────────────

    public List<MemberSearchResult> SearchMembers(string pattern)
    {
        EnsureLoaded();
        var results = new List<MemberSearchResult>();
        foreach (var type in _decompiler!.TypeSystem.MainModule.TypeDefinitions)
        {
            try
            {
                if (type.FullName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    results.Add(new MemberSearchResult("type", type.FullName, GetKind(type), null));
                foreach (var m in type.Methods)
                    if (m.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        results.Add(new MemberSearchResult("method", $"{type.FullName}.{m.Name}", $"{m.ReturnType.Name}({string.Join(", ", m.Parameters.Select(p => p.Type.Name))})", type.FullName));
                foreach (var f in type.Fields)
                    if (f.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        results.Add(new MemberSearchResult("field", $"{type.FullName}.{f.Name}", f.Type.Name, type.FullName));
                foreach (var p in type.Properties)
                    if (p.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        results.Add(new MemberSearchResult("property", $"{type.FullName}.{p.Name}", p.ReturnType.Name, type.FullName));
            }
            catch { continue; }
        }
        return results;
    }

    // ── PE info ───────────────────────────────────────────────────────────────

    public PEInfo GetPEInfo()
    {
        using var stream = File.OpenRead(_binaryPath);
        using var pe = new PEReader(stream);
        if (!pe.HasMetadata) throw new InvalidOperationException("Not a managed .NET assembly");
        var meta = pe.GetMetadataReader();
        var hdrs = pe.PEHeaders;
        var asm = meta.GetAssemblyDefinition();
        var asmName = meta.GetString(asm.Name);
        var ver = asm.Version.ToString();
        bool signed = (asm.Flags & System.Reflection.AssemblyFlags.PublicKey) != 0;
        var sections = hdrs.SectionHeaders.Select(s => s.Name.TrimEnd('\0')).ToList();
        string rt = hdrs.CorHeader != null ? $"{hdrs.CorHeader.MajorRuntimeVersion}.{hdrs.CorHeader.MinorRuntimeVersion}" : "unknown";
        var attrs = new Dictionary<string, string>();
        foreach (var ah in asm.GetCustomAttributes())
        {
            try
            {
                var a = meta.GetCustomAttribute(ah);
                if (a.Constructor.Kind != HandleKind.MemberReference) continue;
                var mr = meta.GetMemberReference((MemberReferenceHandle)a.Constructor);
                if (mr.Parent.Kind != HandleKind.TypeReference) continue;
                var tn = meta.GetString(meta.GetTypeReference((TypeReferenceHandle)mr.Parent).Name);
                if (tn == "TargetFrameworkAttribute")
                {
                    var br = meta.GetBlobReader(a.Value);
                    br.ReadUInt16();
                    var v = br.ReadSerializedString();
                    if (v != null) attrs["TargetFramework"] = v;
                }
            }
            catch { }
        }
        return new PEInfo(hdrs.CoffHeader.Machine.ToString(), hdrs.PEHeader?.Magic == PEMagic.PE32Plus, pe.HasMetadata, attrs.GetValueOrDefault("TargetFramework", "unknown"), asmName, ver, signed, rt, sections, attrs);
    }

    // ── Resources ─────────────────────────────────────────────────────────────

    public List<ResourceInfo> GetResources()
    {
        using var stream = File.OpenRead(_binaryPath);
        using var pe = new PEReader(stream);
        var meta = pe.GetMetadataReader();
        return meta.ManifestResources.Select(h =>
        {
            var r = meta.GetManifestResource(h);
            return new ResourceInfo(meta.GetString(r.Name), r.Implementation.IsNil ? "embedded" : "linked", r.Offset);
        }).ToList();
    }

    // ── Token resolution ──────────────────────────────────────────────────────

    public MetadataTokenResult ResolveToken(string tokenHex)
    {
        var tv = Convert.ToInt32(tokenHex.Replace("0x","").Replace("0X",""), 16);
        int tbl = (tv >> 24) & 0xFF, row = tv & 0x00FFFFFF;
        string tblName = tbl switch { 0x01=>"TypeRef",0x02=>"TypeDef",0x04=>"Field",0x06=>"Method",0x08=>"Param",0x0A=>"MemberRef",0x11=>"StandAloneSig",0x14=>"Event",0x17=>"Property",0x1A=>"ModuleRef",0x1B=>"TypeSpec",0x20=>"Assembly",0x23=>"AssemblyRef",0x70=>"UserString", _ => $"Table0x{tbl:X2}" };
        string? fullName = null, details = null;
        using var stream = File.OpenRead(_binaryPath);
        using var pe = new PEReader(stream);
        var meta = pe.GetMetadataReader();
        try
        {
        if (tbl == 0x02)
        {
            var handle = meta.TypeDefinitions.Skip(row - 1).FirstOrDefault();
            if (!handle.IsNil) { var td = meta.GetTypeDefinition(handle); var ns = meta.GetString(td.Namespace); var nm = meta.GetString(td.Name); fullName = string.IsNullOrEmpty(ns) ? nm : $"{ns}.{nm}"; }
        }
        else if (tbl == 0x06)
        {
            int mr = 0; bool found = false;
            foreach (var th in meta.TypeDefinitions) { foreach (var mh in meta.GetTypeDefinition(th).GetMethods()) { mr++; if (mr == row) { fullName = meta.GetString(meta.GetMethodDefinition(mh).Name); found = true; break; } } if (found) break; }
        }
        else if (tbl == 0x04)
        {
            int fr = 0; bool found = false;
            foreach (var th in meta.TypeDefinitions) { foreach (var fh in meta.GetTypeDefinition(th).GetFields()) { fr++; if (fr == row) { fullName = meta.GetString(meta.GetFieldDefinition(fh).Name); found = true; break; } } if (found) break; }
        }
        else if (tbl == 0x70) { fullName = $"<UserString @0x{row:X}>"; details = "Use --search-string for string search"; }
        }
        catch (Exception ex) { details = $"Error: {ex.Message}"; }

        return new MetadataTokenResult($"0x{tv:X8}", tblName, row, fullName, details);
    }

    // ── P/Invoke listing ──────────────────────────────────────────────────────

    public List<Dictionary<string, object?>> ListPInvokes()
    {
        EnsureLoaded();
        var results = new List<Dictionary<string, object?>>();
        foreach (var type in _decompiler!.TypeSystem.MainModule.TypeDefinitions)
            foreach (var m in type.Methods)
            {
                try
                {
                    if (!m.GetAttributes().Any(a => a.AttributeType.Name == "DllImportAttribute")) continue;
                    results.Add(new Dictionary<string, object?> { {"DeclaringType",type.FullName},{"Method",m.Name},{"FullName",type.FullName+"."+m.Name},{"ReturnType",m.ReturnType.FullName},{"Parameters",m.Parameters.Select(p=>$"{p.Type.FullName} {p.Name}").ToList()} });
                }
                catch { continue; }
            }
        return results;
    }

    // ── Attribute search ──────────────────────────────────────────────────────

    public List<Dictionary<string, object?>> FindAttributes(string attributeName)
    {
        EnsureLoaded();
        var results = new List<Dictionary<string, object?>>();
        foreach (var type in _decompiler!.TypeSystem.MainModule.TypeDefinitions)
        {
            try
            {
                var ta = type.GetAttributes().Where(a => a.AttributeType.Name.Contains(attributeName, StringComparison.OrdinalIgnoreCase)).Select(a => a.AttributeType.FullName).ToList();
                if (ta.Any()) results.Add(new Dictionary<string, object?> {{"MemberKind","type"},{"FullName",type.FullName},{"Attributes",ta}});
                foreach (var m in type.Methods)
                {
                    var ma = m.GetAttributes().Where(a => a.AttributeType.Name.Contains(attributeName, StringComparison.OrdinalIgnoreCase)).Select(a => a.AttributeType.FullName).ToList();
                    if (ma.Any()) results.Add(new Dictionary<string, object?> {{"MemberKind","method"},{"FullName",type.FullName+"."+m.Name},{"Attributes",ma}});
                }
            }
            catch { continue; }
        }
        return results;
    }

    // ── Type / method inspection ──────────────────────────────────────────────

    public TypeDetailInfo InspectType(string typeName, bool includeSource = false)
    {
        EnsureLoaded();
        var t = FindType(typeName);
        string? src = null;
        if (includeSource) try { src = _decompiler!.DecompileTypeAsString(new FullTypeName(typeName)); } catch { }
        return new TypeDetailInfo
        {
            FullName = t.FullName, Namespace = t.Namespace, Kind = GetKind(t),
            BaseType = t.DirectBaseTypes.FirstOrDefault(b => b.Kind != TypeKind.Interface)?.FullName,
            IsAbstract = t.IsAbstract, IsSealed = t.IsSealed, IsInterface = t.Kind == TypeKind.Interface,
            IsPublic = t.Accessibility == Accessibility.Public,
            Fields = t.Fields.Select(f => new FieldSummary(f.Name, f.Type.FullName, f.Accessibility == Accessibility.Public, f.IsStatic, f.IsReadOnly)).ToList(),
            Methods = t.Methods.Select(m => new MethodSummary(m.Name, t.FullName+"."+m.Name, m.ReturnType.FullName, m.Accessibility==Accessibility.Public, m.IsStatic, m.IsAbstract, m.IsVirtual, m.Parameters.Select(p=>p.Type.FullName+" "+p.Name).ToList())).ToList(),
            Properties = t.Properties.Select(p => new PropertySummary(p.Name, p.ReturnType.FullName, p.CanGet, p.CanSet, p.Accessibility==Accessibility.Public, p.IsStatic)).ToList(),
            Interfaces = t.DirectBaseTypes.Where(b => b.Kind==TypeKind.Interface).Select(b=>b.FullName).ToList(),
            DecompiledSource = src
        };
    }

    public MethodDetailInfo InspectMethod(string typeName, string methodName, bool includeSource = true, bool includeIL = false)
    {
        EnsureLoaded();
        var t = FindType(typeName);
        var m = FindMethod(t, methodName);
        string? src = null;
        if (includeSource) try { src = _decompiler!.DecompileAsString(m.MetadataToken); } catch { }
        return new MethodDetailInfo
        {
            Name = m.Name, FullName = t.FullName+"."+m.Name, ReturnType = m.ReturnType.FullName,
            IsPublic = m.Accessibility==Accessibility.Public, IsStatic = m.IsStatic, IsAbstract = m.IsAbstract, IsVirtual = m.IsVirtual,
            Parameters = m.Parameters.Select(p => new Dictionary<string, object?>{{"Name",p.Name},{"Type",p.Type.FullName}}).ToList(),
            DeclaringType = t.FullName, DecompiledSource = src,
            ILCode = includeIL ? DumpIL(typeName, methodName) : null
        };
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ITypeDefinition FindType(string typeName)
    {
        EnsureLoaded();
        var t = _decompiler!.TypeSystem.FindType(new FullTypeName(typeName)).GetDefinition();
        if (t == null) throw new TypeLoadException($"Type not found: '{typeName}'");
        return t;
    }

    private static IMethod FindMethod(ITypeDefinition type, string name)
    {
        var m = type.Methods.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (m == null) throw new InvalidOperationException($"Method '{name}' not found in '{type.FullName}'");
        return m;
    }

    private static string GetKind(ITypeDefinition t) => t.Kind switch
    {
        TypeKind.Class => "class", TypeKind.Interface => "interface",
        TypeKind.Struct => "struct", TypeKind.Enum => "enum",
        TypeKind.Delegate => "delegate", _ => "unknown"
    };
}
