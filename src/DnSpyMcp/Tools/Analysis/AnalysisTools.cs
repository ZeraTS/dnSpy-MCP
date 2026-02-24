using System.ComponentModel;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using DnSpyMcp.Core;
using DnSpyMcp.Models;
using ICSharpCode.Decompiler.TypeSystem;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Analysis;

[McpServerToolType]
public class AnalysisTools
{
    private readonly AssemblyCache _cache;

    public AnalysisTools(AssemblyCache cache)
    {
        _cache = cache;
    }

    [McpServerTool(Name = "get_pe_info"), Description("Get PE/COFF header information, assembly metadata, and target framework of a .NET assembly")]
    public PEInfo GetPEInfo(
        [Description("Absolute or relative path to the .NET assembly (.dll or .exe)")] string assemblyPath)
    {
        try
        {
            var abs = Path.GetFullPath(assemblyPath);
            using var stream = File.OpenRead(abs);
            using var pe = new PEReader(stream);
            if (!pe.HasMetadata) throw new InvalidOperationException("Not a managed .NET assembly");
            var meta = pe.GetMetadataReader();
            var hdrs = pe.PEHeaders;
            var asm = meta.GetAssemblyDefinition();
            var asmName = meta.GetString(asm.Name);
            var ver = asm.Version.ToString();
            bool signed = (asm.Flags & System.Reflection.AssemblyFlags.PublicKey) != 0;
            var sections = hdrs.SectionHeaders.Select(s => s.Name.TrimEnd('\0')).ToList();
            string rt = hdrs.CorHeader != null
                ? $"{hdrs.CorHeader.MajorRuntimeVersion}.{hdrs.CorHeader.MinorRuntimeVersion}"
                : "unknown";
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
            return new PEInfo(
                hdrs.CoffHeader.Machine switch {
                System.Reflection.PortableExecutable.Machine.Amd64   => "x64",
                System.Reflection.PortableExecutable.Machine.I386    => "x86",
                System.Reflection.PortableExecutable.Machine.Arm64   => "ARM64",
                System.Reflection.PortableExecutable.Machine.Arm     => "ARM",
                System.Reflection.PortableExecutable.Machine.IA64    => "IA64",
                var m                                                 => $"0x{(ushort)m:X4}",
            },
                hdrs.PEHeader?.Magic == PEMagic.PE32Plus,
                pe.HasMetadata,
                attrs.GetValueOrDefault("TargetFramework", "unknown"),
                asmName,
                ver,
                signed,
                rt,
                sections,
                attrs);
        }
        catch (Exception ex)
        {
            return new PEInfo($"ERROR: {ex.Message}", false, false, "", "", "", false, "", [], []);
        }
    }

    [McpServerTool(Name = "get_resources"), Description("List all manifest resources embedded in the assembly")]
    public List<ResourceInfo> GetResources(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath)
    {
        try
        {
            var abs = Path.GetFullPath(assemblyPath);
            using var stream = File.OpenRead(abs);
            using var pe = new PEReader(stream);
            var meta = pe.GetMetadataReader();
            return meta.ManifestResources.Select(h =>
            {
                var r = meta.GetManifestResource(h);
                return new ResourceInfo(
                    meta.GetString(r.Name),
                    r.Implementation.IsNil ? "embedded" : "linked",
                    r.Offset);
            }).ToList();
        }
        catch (Exception ex)
        {
            return [new ResourceInfo($"ERROR: {ex.Message}", "error", 0)];
        }
    }

    [McpServerTool(Name = "resolve_token"), Description("Resolve a metadata token (hex, e.g. '0x02000001') to its definition")]
    public MetadataTokenResult ResolveToken(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Metadata token as hex string (e.g. '0x06000001')")] string tokenHex)
    {
        try
        {
            var tv = Convert.ToInt32(tokenHex.Replace("0x", "").Replace("0X", ""), 16);
            int tbl = (tv >> 24) & 0xFF, row = tv & 0x00FFFFFF;
            string tblName = tbl switch
            {
                0x01 => "TypeRef", 0x02 => "TypeDef", 0x04 => "Field",
                0x06 => "Method", 0x08 => "Param", 0x0A => "MemberRef",
                0x11 => "StandAloneSig", 0x14 => "Event", 0x17 => "Property",
                0x1A => "ModuleRef", 0x1B => "TypeSpec", 0x20 => "Assembly",
                0x23 => "AssemblyRef", 0x70 => "UserString",
                _ => $"Table0x{tbl:X2}"
            };
            string? fullName = null, details = null;
            var abs = Path.GetFullPath(assemblyPath);
            using var stream = File.OpenRead(abs);
            using var pe = new PEReader(stream);
            var meta = pe.GetMetadataReader();
            try
            {
                if (tbl == 0x02)
                {
                    var handle = meta.TypeDefinitions.Skip(row - 1).FirstOrDefault();
                    if (!handle.IsNil)
                    {
                        var td = meta.GetTypeDefinition(handle);
                        var ns = meta.GetString(td.Namespace);
                        var nm = meta.GetString(td.Name);
                        fullName = string.IsNullOrEmpty(ns) ? nm : $"{ns}.{nm}";
                    }
                }
                else if (tbl == 0x06)
                {
                    int mr = 0; bool found = false;
                    foreach (var th in meta.TypeDefinitions)
                    {
                        foreach (var mh in meta.GetTypeDefinition(th).GetMethods())
                        {
                            mr++;
                            if (mr == row) { fullName = meta.GetString(meta.GetMethodDefinition(mh).Name); found = true; break; }
                        }
                        if (found) break;
                    }
                }
                else if (tbl == 0x04)
                {
                    int fr = 0; bool found = false;
                    foreach (var th in meta.TypeDefinitions)
                    {
                        foreach (var fh in meta.GetTypeDefinition(th).GetFields())
                        {
                            fr++;
                            if (fr == row) { fullName = meta.GetString(meta.GetFieldDefinition(fh).Name); found = true; break; }
                        }
                        if (found) break;
                    }
                }
                else if (tbl == 0x70)
                {
                    fullName = $"<UserString @0x{row:X}>";
                    details = "Use search_strings for string search";
                }
            }
            catch (Exception ex) { details = $"Error: {ex.Message}"; }

            return new MetadataTokenResult($"0x{tv:X8}", tblName, row, fullName, details);
        }
        catch (Exception ex)
        {
            return new MetadataTokenResult(tokenHex, "error", 0, null, ex.Message);
        }
    }

    [McpServerTool(Name = "list_pinvokes"), Description("List all P/Invoke (DllImport) declarations in the assembly")]
    public List<Dictionary<string, object?>> ListPInvokes(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            var results = new List<Dictionary<string, object?>>();
            foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
                foreach (var m in type.Methods)
                {
                    try
                    {
                        if (!m.GetAttributes().Any(a => a.AttributeType.Name == "DllImportAttribute")) continue;
                        var dllImport = m.GetAttributes().FirstOrDefault(a => a.AttributeType.Name == "DllImportAttribute");
                        string? dllName = null;
                        string? entryPoint = null;
                        if (dllImport != null)
                        {
                            var fixedArgs = dllImport.FixedArguments;
                            if (fixedArgs.Any()) dllName = fixedArgs[0].Value?.ToString();
                            var namedArgs = dllImport.NamedArguments;
                            var ep = namedArgs.FirstOrDefault(a => a.Name == "EntryPoint");
                            entryPoint = ep.Value?.ToString();
                        }
                        results.Add(new Dictionary<string, object?>
                        {
                            {"DeclaringType", type.FullName},
                            {"Method", m.Name},
                            {"FullName", type.FullName + "." + m.Name},
                            {"DllName", dllName},
                            {"EntryPoint", entryPoint ?? m.Name},
                            {"ReturnType", m.ReturnType.FullName},
                            {"Parameters", m.Parameters.Select(p => $"{p.Type.FullName} {p.Name}").ToList()}
                        });
                    }
                    catch { continue; }
                }
            return results;
        }
        catch (Exception ex)
        {
            return [new Dictionary<string, object?> { {"error", ex.Message} }];
        }
    }

    [McpServerTool(Name = "find_attributes"), Description("Find all types and methods decorated with a specific attribute")]
    public List<Dictionary<string, object?>> FindAttributes(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Attribute name (or partial name) to search for (case-insensitive)")] string attributeName)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            var results = new List<Dictionary<string, object?>>();
            foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
            {
                try
                {
                    var ta = type.GetAttributes()
                        .Where(a => a.AttributeType.Name.Contains(attributeName, StringComparison.OrdinalIgnoreCase))
                        .Select(a => a.AttributeType.FullName).ToList();
                    if (ta.Any())
                        results.Add(new Dictionary<string, object?> { {"MemberKind", "type"}, {"FullName", type.FullName}, {"Attributes", ta} });
                    foreach (var m in type.Methods)
                    {
                        var ma = m.GetAttributes()
                            .Where(a => a.AttributeType.Name.Contains(attributeName, StringComparison.OrdinalIgnoreCase))
                            .Select(a => a.AttributeType.FullName).ToList();
                        if (ma.Any())
                            results.Add(new Dictionary<string, object?> { {"MemberKind", "method"}, {"FullName", type.FullName + "." + m.Name}, {"Attributes", ma} });
                    }
                }
                catch { continue; }
            }
            return results;
        }
        catch (Exception ex)
        {
            return [new Dictionary<string, object?> { {"error", ex.Message} }];
        }
    }

    [McpServerTool(Name = "get_methods_for_type"), Description("Get all methods defined on a specific type")]
    public List<MethodSummary> GetMethodsForType(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Full type name (e.g. 'Namespace.ClassName')")] string typeName)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            var type = decompiler.TypeSystem.FindType(new FullTypeName(typeName)).GetDefinition();
            if (type == null) throw new TypeLoadException($"Type not found: '{typeName}'");
            return type.Methods.Select(m =>
            {
                try
                {
                    return new MethodSummary(
                        m.Name,
                        type.FullName + "." + m.Name,
                        m.ReturnType.FullName,
                        m.Accessibility == Accessibility.Public,
                        m.IsStatic,
                        m.IsAbstract,
                        m.IsVirtual,
                        m.Parameters.Select(p => p.Type.FullName + " " + p.Name).ToList());
                }
                catch { return null; }
            }).Where(m => m != null).Cast<MethodSummary>().ToList();
        }
        catch (Exception ex)
        {
            return [new MethodSummary($"ERROR: {ex.Message}", "", "", false, false, false, false, [])];
        }
    }
}
