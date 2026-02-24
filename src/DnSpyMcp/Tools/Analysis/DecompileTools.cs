using System.ComponentModel;
using System.Text;
using System.Threading;
using DnSpyMcp.Core;
using ICSharpCode.Decompiler.Disassembler;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.TypeSystem;
using System.Reflection.PortableExecutable;
using ModelContextProtocol.Server;

namespace DnSpyMcp.Tools.Analysis;

[McpServerToolType]
public class DecompileTools
{
    private readonly AssemblyCache _cache;

    public DecompileTools(AssemblyCache cache)
    {
        _cache = cache;
    }

    [McpServerTool(Name = "decompile_assembly"), Description("Decompile the entire assembly to C# source code")]
    public string DecompileAssembly(
        [Description("Absolute or relative path to the .NET assembly (.dll or .exe)")] string assemblyPath)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            return decompiler.DecompileWholeModuleAsString();
        }
        catch (Exception ex)
        {
            return $"// Error decompiling assembly: {ex.Message}";
        }
    }

    [McpServerTool(Name = "decompile_type"), Description("Decompile a specific type to C# source code")]
    public string DecompileType(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Full type name (e.g. 'Namespace.ClassName' or 'Namespace.Outer+Inner')")] string typeName)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            return decompiler.DecompileTypeAsString(new FullTypeName(typeName));
        }
        catch (Exception ex)
        {
            return $"// Error decompiling type {typeName}: {ex.Message}";
        }
    }

    [McpServerTool(Name = "decompile_method"), Description("Decompile a specific method to C# source code")]
    public string DecompileMethod(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Full type name containing the method")] string typeName,
        [Description("Method name (first match, case-insensitive)")] string methodName)
    {
        try
        {
            var (decompiler, _) = _cache.GetOrLoad(assemblyPath);
            var type = FindType(decompiler, typeName);
            var method = FindMethod(type, methodName);
            return decompiler.DecompileAsString(method.MetadataToken);
        }
        catch (Exception ex)
        {
            return $"// Error decompiling {typeName}.{methodName}: {ex.Message}";
        }
    }

    [McpServerTool(Name = "dump_il"), Description("Dump IL (CIL) disassembly for the whole assembly, a type, or a specific method")]
    public string DumpIL(
        [Description("Absolute or relative path to the .NET assembly")] string assemblyPath,
        [Description("Optional: full type name to filter to")] string? typeName = null,
        [Description("Optional: method name to filter to (requires typeName)")] string? methodName = null)
    {
        var sb = new StringBuilder();
        var output = new PlainTextOutput(new StringWriter(sb));
        try
        {
            var abs = Path.GetFullPath(assemblyPath);
            using var stream = File.OpenRead(abs);
            var module = new PEFile(abs, stream, PEStreamOptions.Default);
            var dis = new ReflectionDisassembler(output, CancellationToken.None);

            if (typeName == null)
            {
                dis.WriteModuleContents(module);
            }
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

                    if (methodName == null)
                    {
                        dis.DisassembleType(module, th);
                    }
                    else
                    {
                        foreach (var mh in td.GetMethods())
                        {
                            var md = meta.GetMethodDefinition(mh);
                            if (meta.GetString(md.Name).Equals(methodName, StringComparison.OrdinalIgnoreCase))
                            {
                                dis.DisassembleMethod(module, mh);
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine($"// IL dump error: {ex.Message}");
        }
        return sb.ToString();
    }

    private static ITypeDefinition FindType(ICSharpCode.Decompiler.CSharp.CSharpDecompiler decompiler, string typeName)
    {
        var t = decompiler.TypeSystem.FindType(new FullTypeName(typeName)).GetDefinition();
        if (t == null) throw new TypeLoadException($"Type not found: '{typeName}'");
        return t;
    }

    private static IMethod FindMethod(ITypeDefinition type, string name)
    {
        var m = type.Methods.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (m == null) throw new InvalidOperationException($"Method '{name}' not found in '{type.FullName}'");
        return m;
    }
}
