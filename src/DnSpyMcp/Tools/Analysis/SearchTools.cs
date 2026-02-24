using System.ComponentModel;
using System.Text.RegularExpressions;
using DnSpyMcp.Core;
using DnSpyMcp.Models;
using ICSharpCode.Decompiler.TypeSystem;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Analysis;

[McpServerToolType]
public class SearchTools
{
    private readonly AssemblyCache _cache;

    public SearchTools(AssemblyCache cache)
    {
        _cache = cache;
    }

    [McpServerTool(Name = "list_types"), Description("List all type definitions in the assembly")]
    public List<TypeInfo> ListTypes(
        [Description("Absolute or relative path to the .NET assembly (.dll or .exe)")] string assemblyPath)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            return decompiler.TypeSystem.MainModule.TypeDefinitions
                .Select(t =>
                {
                    try
                    {
                        return new TypeInfo(
                            t.FullName,
                            t.Namespace,
                            GetKind(t),
                            t.Accessibility == Accessibility.Public,
                            t.IsAbstract,
                            t.IsSealed,
                            t.DirectBaseTypes.Where(b => b.Kind == TypeKind.Interface)
                                .Select(b => b.FullName).ToList());
                    }
                    catch { return null; }
                })
                .Where(t => t != null).Cast<TypeInfo>()
                .OrderBy(t => t.FullName).ToList();
        }
        catch (Exception ex)
        {
            return [new TypeInfo($"ERROR: {ex.Message}", "", "error", false, false, false, [])];
        }
    }

    [McpServerTool(Name = "find_methods"), Description("Find methods in the assembly, optionally filtered by name pattern")]
    public List<MethodSummary> FindMethods(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Optional substring to filter method names (case-insensitive)")] string? pattern = null)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            var results = new List<MethodSummary>();
            foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
                foreach (var m in type.Methods)
                {
                    try
                    {
                        if (pattern != null && !m.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;
                        results.Add(new MethodSummary(
                            m.Name,
                            type.FullName + "." + m.Name,
                            m.ReturnType.FullName,
                            m.Accessibility == Accessibility.Public,
                            m.IsStatic,
                            m.IsAbstract,
                            m.IsVirtual,
                            m.Parameters.Select(p => p.Type.FullName + " " + p.Name).ToList()));
                    }
                    catch { continue; }
                }
            return results;
        }
        catch (Exception ex)
        {
            return [new MethodSummary($"ERROR: {ex.Message}", "", "", false, false, false, false, [])];
        }
    }

    [McpServerTool(Name = "search_strings"), Description("Search for string literals in the assembly's decompiled source")]
    public List<StringSearchResult> SearchStrings(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Search pattern (substring or regex)")] string pattern,
        [Description("If true, treat pattern as a regular expression")] bool useRegex = false)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            var results = new List<StringSearchResult>();
            Func<string, bool> match = useRegex
                ? s => Regex.IsMatch(s, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
                : s => s.Contains(pattern, StringComparison.OrdinalIgnoreCase);

            var strRegex = new Regex("\"((?:[^\"\\\\]|\\\\.)*)\"", RegexOptions.Compiled);

            foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    try
                    {
                        var src = decompiler.DecompileAsString(method.MetadataToken);
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

            return results
                .GroupBy(r => r.Value + "|" + r.FoundInType + "|" + r.FoundInMethod)
                .Select(g => g.First())
                .ToList();
        }
        catch (Exception ex)
        {
            return [new StringSearchResult($"ERROR: {ex.Message}", "", "")];
        }
    }

    [McpServerTool(Name = "search_members"), Description("Search for types, methods, fields, and properties by name pattern")]
    public List<MemberSearchResult> SearchMembers(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Substring to search for in member names (case-insensitive)")] string pattern)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            var results = new List<MemberSearchResult>();
            foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
            {
                try
                {
                    if (type.FullName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        results.Add(new MemberSearchResult("type", type.FullName, GetKind(type), null));
                    foreach (var m in type.Methods)
                        if (m.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            results.Add(new MemberSearchResult("method", $"{type.FullName}.{m.Name}",
                                $"{m.ReturnType.Name}({string.Join(", ", m.Parameters.Select(p => p.Type.Name))})", type.FullName));
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
        catch (Exception ex)
        {
            return [new MemberSearchResult("error", $"ERROR: {ex.Message}", null, null)];
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
