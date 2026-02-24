using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace dnSpyMCP.AutomatedDebugger;

public class Debugger
{
    private readonly string _binaryPath;
    private Assembly? _assembly;

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
            var data = File.ReadAllBytes(_binaryPath);
            _assembly = Assembly.Load(data);
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to load assembly: {ex.Message}");
            return false;
        }
    }

    public List<MethodInfo> FindMethods(string? methodName = null)
    {
        if (_assembly == null)
            throw new InvalidOperationException("Assembly not loaded");

        var methods = new List<MethodInfo>();

        foreach (var type in _assembly.GetTypes())
        {
            try
            {
                var typeMethods = type.GetMethods(
                    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance
                );

                foreach (var method in typeMethods)
                {
                    if (methodName == null || method.Name.Contains(methodName, StringComparison.OrdinalIgnoreCase))
                    {
                        methods.Add(method);
                    }
                }
            }
            catch
            {
                continue;
            }
        }

        return methods;
    }

    public List<string> GetAllTypes()
    {
        if (_assembly == null)
            throw new InvalidOperationException("Assembly not loaded");

        return _assembly.GetTypes().Select(t => t.FullName ?? t.Name).ToList();
    }

    public object? InvokeMethod(string typeName, string methodName, object?[]? parameters = null)
    {
        if (_assembly == null)
            throw new InvalidOperationException("Assembly not loaded");

        var type = _assembly.GetType(typeName);
        if (type == null)
            throw new TypeLoadException($"Type not found: {typeName}");

        var method = type.GetMethod(methodName,
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance,
            null,
            parameters?.Select(p => p?.GetType() ?? typeof(object)).ToArray() ?? Type.EmptyTypes,
            null
        );

        if (method == null)
            throw new MethodAccessException($"Method not found: {methodName}");

        try
        {
            return method.Invoke(null, parameters ?? Array.Empty<object?>());
        }
        catch (TargetInvocationException ex)
        {
            throw new InvalidOperationException($"Method invocation failed: {ex.InnerException?.Message}", ex.InnerException);
        }
    }

    public Dictionary<string, object?> InspectType(string typeName)
    {
        if (_assembly == null)
            throw new InvalidOperationException("Assembly not loaded");

        var type = _assembly.GetType(typeName);
        if (type == null)
            throw new TypeLoadException($"Type not found: {typeName}");

        var info = new Dictionary<string, object?>
        {
            { "Name", type.FullName },
            { "BaseType", type.BaseType?.FullName },
            { "IsAbstract", type.IsAbstract },
            { "IsSealed", type.IsSealed },
            { "IsInterface", type.IsInterface },
            { "Namespace", type.Namespace }
        };

        var fields = new List<Dictionary<string, object?>>();
        foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance))
        {
            fields.Add(new Dictionary<string, object?>
            {
                { "Name", field.Name },
                { "Type", field.FieldType.Name },
                { "IsPublic", field.IsPublic },
                { "IsStatic", field.IsStatic }
            });
        }
        info["Fields"] = fields;

        var methods = new List<Dictionary<string, object?>>();
        foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance))
        {
            methods.Add(new Dictionary<string, object?>
            {
                { "Name", method.Name },
                { "ReturnType", method.ReturnType.Name },
                { "IsPublic", method.IsPublic },
                { "IsStatic", method.IsStatic },
                { "ParameterCount", method.GetParameters().Length }
            });
        }
        info["Methods"] = methods;

        return info;
    }

    public Dictionary<string, object?> InspectMethod(string typeName, string methodName)
    {
        if (_assembly == null)
            throw new InvalidOperationException("Assembly not loaded");

        var type = _assembly.GetType(typeName);
        if (type == null)
            throw new TypeLoadException($"Type not found: {typeName}");

        var method = type.GetMethod(methodName,
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance
        );

        if (method == null)
            throw new MethodAccessException($"Method not found: {methodName}");

        var parameters = new List<Dictionary<string, object?>>();
        foreach (var param in method.GetParameters())
        {
            parameters.Add(new Dictionary<string, object?>
            {
                { "Name", param.Name },
                { "Type", param.ParameterType.Name },
                { "HasDefaultValue", param.HasDefaultValue },
                { "DefaultValue", param.HasDefaultValue ? param.DefaultValue : null }
            });
        }

        return new Dictionary<string, object?>
        {
            { "Name", method.Name },
            { "FullName", method.DeclaringType?.FullName + "." + method.Name },
            { "ReturnType", method.ReturnType.Name },
            { "IsPublic", method.IsPublic },
            { "IsStatic", method.IsStatic },
            { "Parameters", parameters },
            { "DeclaringType", method.DeclaringType?.FullName }
        };
    }
}
