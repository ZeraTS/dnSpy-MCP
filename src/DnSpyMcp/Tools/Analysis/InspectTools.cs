using System.ComponentModel;
using DnSpyMcp.Core;
using DnSpyMcp.Models;
using ICSharpCode.Decompiler.TypeSystem;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Analysis;

[McpServerToolType]
public class InspectTools
{
    private readonly AssemblyCache _cache;

    public InspectTools(AssemblyCache cache)
    {
        _cache = cache;
    }

    [McpServerTool(Name = "inspect_type"), Description("Inspect a type's structure: fields, methods, properties, interfaces, and optionally its decompiled source")]
    public TypeDetailInfo InspectType(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Full type name (e.g. 'Namespace.ClassName')")] string typeName,
        [Description("If true, include decompiled C# source for the type")] bool includeSource = false)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            var t = decompiler.TypeSystem.FindType(new FullTypeName(typeName)).GetDefinition();
            if (t == null) throw new TypeLoadException($"Type not found: '{typeName}'");

            string? src = null;
            if (includeSource)
            {
                try { src = decompiler.DecompileTypeAsString(new FullTypeName(typeName)); }
                catch { }
            }

            return new TypeDetailInfo
            {
                FullName = t.FullName,
                Namespace = t.Namespace,
                Kind = GetKind(t),
                BaseType = t.DirectBaseTypes.FirstOrDefault(b => b.Kind != TypeKind.Interface)?.FullName,
                IsAbstract = t.IsAbstract,
                IsSealed = t.IsSealed,
                IsInterface = t.Kind == TypeKind.Interface,
                IsPublic = t.Accessibility == Accessibility.Public,
                Fields = t.Fields.Select(f => new FieldSummary(
                    f.Name, f.Type.FullName,
                    f.Accessibility == Accessibility.Public,
                    f.IsStatic, f.IsReadOnly)).ToList(),
                Methods = t.Methods.Select(m => new MethodSummary(
                    m.Name, t.FullName + "." + m.Name, m.ReturnType.FullName,
                    m.Accessibility == Accessibility.Public, m.IsStatic, m.IsAbstract, m.IsVirtual,
                    m.Parameters.Select(p => p.Type.FullName + " " + p.Name).ToList())).ToList(),
                Properties = t.Properties.Select(p => new PropertySummary(
                    p.Name, p.ReturnType.FullName, p.CanGet, p.CanSet,
                    p.Accessibility == Accessibility.Public, p.IsStatic)).ToList(),
                Interfaces = t.DirectBaseTypes
                    .Where(b => b.Kind == TypeKind.Interface)
                    .Select(b => b.FullName).ToList(),
                DecompiledSource = src
            };
        }
        catch (Exception ex)
        {
            return new TypeDetailInfo { FullName = $"ERROR: {ex.Message}" };
        }
    }

    [McpServerTool(Name = "inspect_method"), Description("Inspect a specific method: signature, parameters, decompiled source, and optionally IL code")]
    public MethodDetailInfo InspectMethod(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Full type name containing the method")] string typeName,
        [Description("Method name (first match, case-insensitive)")] string methodName,
        [Description("If true, include decompiled C# source")] bool includeSource = true,
        [Description("If true, include IL disassembly")] bool includeIL = false)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            var t = decompiler.TypeSystem.FindType(new FullTypeName(typeName)).GetDefinition();
            if (t == null) throw new TypeLoadException($"Type not found: '{typeName}'");
            var m = t.Methods.FirstOrDefault(x => x.Name.Equals(methodName, StringComparison.OrdinalIgnoreCase));
            if (m == null) throw new InvalidOperationException($"Method '{methodName}' not found in '{typeName}'");

            string? src = null;
            if (includeSource)
            {
                try { src = decompiler.DecompileAsString(m.MetadataToken); }
                catch { }
            }

            string? ilCode = null;
            if (includeIL)
            {
                try
                {
                    var decompileTools = new DecompileTools(_cache);
                    ilCode = decompileTools.DumpIL(assemblyPath, typeName, methodName);
                }
                catch { }
            }

            return new MethodDetailInfo
            {
                Name = m.Name,
                FullName = t.FullName + "." + m.Name,
                ReturnType = m.ReturnType.FullName,
                IsPublic = m.Accessibility == Accessibility.Public,
                IsStatic = m.IsStatic,
                IsAbstract = m.IsAbstract,
                IsVirtual = m.IsVirtual,
                Parameters = m.Parameters.Select(p => new Dictionary<string, object?> { {"Name", p.Name}, {"Type", p.Type.FullName} }).ToList(),
                DeclaringType = t.FullName,
                DecompiledSource = src,
                ILCode = ilCode
            };
        }
        catch (Exception ex)
        {
            return new MethodDetailInfo { Name = $"ERROR: {ex.Message}" };
        }
    }

    private static string GetKind(ITypeDefinition t) => t.Kind switch
    {
        TypeKind.Class => "class",
        TypeKind.Interface => "interface",
        TypeKind.Struct => "struct",
        TypeKind.Enum => "enum",
        TypeKind.Delegate => "delegate",
        _ => "unknown"
    };
}
