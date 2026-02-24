using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using dnSpyMCP.AutomatedDebugger;

namespace dnSpyMCP.CLI;

class Program
{
    static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "--help" or "-h")
        {
            PrintHelp();
            return 0;
        }

        try
        {
            var options = ParseArguments(args);
            return ExecuteCommand(options);
        }
        catch (ArgumentException ex)
        {
            WriteError(ex.Message);
            return 2;
        }
        catch (Exception ex)
        {
            WriteError(ex.Message);
            return 1;
        }
    }

    static CliOptions ParseArguments(string[] args)
    {
        var options = new CliOptions();

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--binary": case "-b":
                    options.BinaryPath = args[++i]; break;
                case "--output": case "-o":
                    options.OutputPath = args[++i]; break;
                case "--json":
                    options.JsonOutput = true; break;
                case "--type": case "-t":
                    options.TypeName = args[++i]; break;
                case "--method": case "-m":
                    options.MethodName = args[++i]; break;
                case "--list-types":
                    options.Command = Command.ListTypes; break;
                case "--list-methods":
                    options.Command = Command.ListMethods; break;
                case "--inspect":
                    options.Command = Command.InspectType;
                    options.TypeName = args[++i]; break;
                case "--inspect-method":
                    options.Command = Command.InspectMethod; break;
                case "--decompile":
                    options.Command = Command.Decompile; break;
                case "--decompile-type":
                    options.Command = Command.DecompileType; break;
                case "--decompile-method":
                    options.Command = Command.DecompileMethod; break;
                case "--dump-il":
                    options.Command = Command.DumpIL; break;
                case "--search-string":
                    options.Command = Command.SearchString;
                    options.SearchPattern = args[++i]; break;
                case "--search-member":
                    options.Command = Command.SearchMember;
                    options.SearchPattern = args[++i]; break;
                case "--pe-info":
                    options.Command = Command.PEInfo; break;
                case "--get-resources":
                    options.Command = Command.GetResources; break;
                case "--list-pinvokes":
                    options.Command = Command.ListPInvokes; break;
                case "--find-attributes":
                    options.Command = Command.FindAttributes;
                    options.SearchPattern = args[++i]; break;
                case "--token":
                    options.Command = Command.ResolveToken;
                    options.Token = args[++i]; break;
                case "--regex":
                    options.UseRegex = true; break;
                case "--include-source":
                    options.IncludeSource = true; break;
                case "--include-il":
                    options.IncludeIL = true; break;
                case "--version": case "-v":
                    Console.WriteLine("dnspy-mcp v1.1.0 (dnSpyEx/ICSharpCode.Decompiler)");
                    Environment.Exit(0); break;
                default:
                    throw new ArgumentException($"Unknown argument: {args[i]}");
            }
        }

        if (string.IsNullOrEmpty(options.BinaryPath))
            throw new ArgumentException("--binary <path> is required");
        if (!File.Exists(options.BinaryPath))
            throw new ArgumentException($"Binary not found: {options.BinaryPath}");

        return options;
    }

    static int ExecuteCommand(CliOptions options)
    {
        var bp = options.BinaryPath!;

        if (options.Command == Command.PEInfo)
        {
            var info = new Debugger(bp).GetPEInfo();
            WriteOutput(info, options);
            return 0;
        }

        if (options.Command == Command.ResolveToken)
        {
            var tokenResult = new Debugger(bp).ResolveToken(
                options.Token ?? throw new ArgumentException("--token <hex> required"));
            WriteOutput(tokenResult, options);
            return 0;
        }

        if (options.Command == Command.GetResources)
        {
            WriteOutput(new Debugger(bp).GetResources(), options);
            return 0;
        }

        if (options.Command == Command.DumpIL)
        {
            WriteRaw(new Debugger(bp).DumpIL(options.TypeName, options.MethodName), options);
            return 0;
        }

        // All other commands need the decompiler loaded
        var d = new Debugger(bp);
        if (!d.LoadAssembly())
        {
            WriteError("Failed to load assembly");
            return 1;
        }

        object? result = options.Command switch
        {
            Command.ListTypes    => d.GetAllTypes(),
            Command.ListMethods  => d.FindMethods(options.MethodName),
            Command.InspectType  => d.InspectType(
                options.TypeName ?? throw new ArgumentException("--type required"),
                options.IncludeSource),
            Command.InspectMethod => d.InspectMethod(
                options.TypeName   ?? throw new ArgumentException("--type required"),
                options.MethodName ?? throw new ArgumentException("--method required"),
                includeSource: true,
                includeIL: options.IncludeIL),
            Command.Decompile       => d.DecompileAssembly(),
            Command.DecompileType   => d.DecompileType(
                options.TypeName ?? throw new ArgumentException("--type required")),
            Command.DecompileMethod => d.DecompileMethod(
                options.TypeName   ?? throw new ArgumentException("--type required"),
                options.MethodName ?? throw new ArgumentException("--method required")),
            Command.SearchString => d.SearchStrings(
                options.SearchPattern ?? throw new ArgumentException("Pattern required"),
                options.UseRegex),
            Command.SearchMember => d.SearchMembers(
                options.SearchPattern ?? throw new ArgumentException("Pattern required")),
            Command.ListPInvokes    => d.ListPInvokes(),
            Command.FindAttributes  => d.FindAttributes(
                options.SearchPattern ?? throw new ArgumentException("Attribute name required")),
            _ => throw new ArgumentException("No command specified. Use --help.")
        };

        if (result is string s) WriteRaw(s, options);
        else WriteOutput(result, options);
        return 0;
    }

    static void WriteOutput(object? data, CliOptions o)
    {
        var text = o.JsonOutput
            ? JsonSerializer.Serialize(data, JsonOpts)
            : data?.ToString() ?? string.Empty;
        Emit(text, o.OutputPath);
    }

    static void WriteRaw(string content, CliOptions o)
    {
        if (o.JsonOutput)
            Emit(JsonSerializer.Serialize(new { content }, JsonOpts), o.OutputPath);
        else
            Emit(content, o.OutputPath);
    }

    static void Emit(string text, string? path)
    {
        if (!string.IsNullOrEmpty(path)) { File.WriteAllText(path, text); Console.Error.WriteLine($"Written to: {path}"); }
        else Console.WriteLine(text);
    }

    static void WriteError(string msg) => Console.Error.WriteLine($"ERROR: {msg}");

    static void PrintHelp() => Console.WriteLine("""
        dnspy-mcp v1.1.0 — Headless .NET Decompiler (ICSharpCode.Decompiler / dnSpyEx)

        USAGE:  dotnet dnspy-mcp.dll --binary <path> <COMMAND> [OPTIONS]

        ENUMERATION:
          --list-types                  List all types
          --list-methods [-m <filter>]  List methods (optional name filter)
          --get-resources               List embedded resources
          --list-pinvokes               List P/Invoke declarations
          --pe-info                     PE headers, TFM, signing info

        DECOMPILATION:
          --decompile                   Whole assembly to C#
          --decompile-type -t <Name>    Specific type to C#
          --decompile-method -t <T> -m <M>  Specific method to C#
          --dump-il [-t <T>] [-m <M>]   Raw IL bytecode

        INSPECTION:
          --inspect <TypeName>          Type detail (fields, methods, props)
          --inspect-method -t <T> -m <M>  Method detail + C# source
            --include-source            Add decompiled C# (for --inspect)
            --include-il                Add IL (for --inspect-method)

        SEARCH:
          --search-string <pattern>     String literals in IL (ldstr scan)
          --search-member <pattern>     Types/methods/fields by name
          --find-attributes <name>      Members with a specific attribute
          --token <0xHHHHHHHH>          Resolve metadata token
          --regex                       Use pattern as regex

        OUTPUT:
          -o, --output <path>           Write to file
          --json                        JSON output (machine-readable)
        """);
}

enum Command
{
    None, ListTypes, ListMethods, InspectType, InspectMethod,
    Decompile, DecompileType, DecompileMethod, DumpIL,
    SearchString, SearchMember, PEInfo, GetResources,
    ListPInvokes, FindAttributes, ResolveToken
}

class CliOptions
{
    public string? BinaryPath { get; set; }
    public string? TypeName { get; set; }
    public string? MethodName { get; set; }
    public string? OutputPath { get; set; }
    public string? SearchPattern { get; set; }
    public string? Token { get; set; }
    public Command Command { get; set; } = Command.None;
    public bool JsonOutput { get; set; }
    public bool UseRegex { get; set; }
    public bool IncludeSource { get; set; }
    public bool IncludeIL { get; set; }
}
