using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using dnSpyMCP.AutomatedDebugger;

namespace dnSpyMCP.CLI;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] == "--help" || args[0] == "-h")
        {
            PrintHelp();
            return 0;
        }

        try
        {
            var options = ParseArguments(args);
            return ExecuteCommand(options);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
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
                case "--binary":
                case "-b":
                    options.BinaryPath = args[++i];
                    break;
                case "--method":
                case "-m":
                    options.Method = args[++i];
                    break;
                case "--type":
                case "-t":
                    options.Type = args[++i];
                    break;
                case "--output":
                case "-o":
                    options.OutputPath = args[++i];
                    break;
                case "--json":
                    options.JsonOutput = true;
                    break;
                case "--list-types":
                    options.ListTypes = true;
                    break;
                case "--list-methods":
                    options.ListMethods = true;
                    break;
                case "--inspect":
                    options.InspectType = args[++i];
                    break;
                case "--version":
                case "-v":
                    Console.WriteLine("dnspy-mcp v1.0.0");
                    Environment.Exit(0);
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {args[i]}");
            }
        }

        if (string.IsNullOrEmpty(options.BinaryPath))
            throw new ArgumentException("--binary path is required");

        return options;
    }

    static int ExecuteCommand(CliOptions options)
    {
        var debugger = new Debugger(options.BinaryPath);

        if (!debugger.LoadAssembly())
            return 1;

        try
        {
            object? result = null;

            if (options.ListTypes)
            {
                result = debugger.GetAllTypes();
            }
            else if (options.ListMethods)
            {
                result = debugger.FindMethods(options.Method);
            }
            else if (!string.IsNullOrEmpty(options.InspectType))
            {
                result = debugger.InspectType(options.InspectType);
            }
            else if (!string.IsNullOrEmpty(options.Type) && !string.IsNullOrEmpty(options.Method))
            {
                result = debugger.InspectMethod(options.Type, options.Method);
            }
            else if (!string.IsNullOrEmpty(options.Method))
            {
                var methods = debugger.FindMethods(options.Method);
                result = methods.Count > 0 ? methods : "No methods found";
            }

            if (result != null)
            {
                string output;
                if (options.JsonOutput)
                {
                    var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
                    output = json;
                }
                else
                {
                    output = result.ToString() ?? string.Empty;
                }

                if (!string.IsNullOrEmpty(options.OutputPath))
                {
                    File.WriteAllText(options.OutputPath, output);
                    Console.WriteLine($"Output written to: {options.OutputPath}");
                }
                else
                {
                    Console.WriteLine(output);
                }
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Execution error: {ex.Message}");
            if (options.JsonOutput)
            {
                var errorJson = JsonSerializer.Serialize(
                    new { Error = ex.Message, Type = ex.GetType().Name },
                    new JsonSerializerOptions { WriteIndented = true }
                );
                Console.Error.WriteLine(errorJson);
            }
            return 1;
        }
    }

    static void PrintHelp()
    {
        Console.WriteLine("""
            dnspy-mcp v1.0.0 - Headless CLI Reflection Debugger

            USAGE:
              dotnet dnspy-mcp.dll --binary <path> [OPTIONS]

            OPTIONS:
              -b, --binary <path>         Path to .NET assembly (required)
              -m, --method <name>         Search for method by name
              -t, --type <name>           Inspect specific type
              --inspect <typename>        Detailed inspection of type
              -o, --output <path>         Write output to file
              --json                      Output results as JSON
              --list-types                List all types in assembly
              --list-methods              List all methods in assembly
              -h, --help                  Show this help message
              -v, --version               Show version

            EXAMPLES:
              dotnet dnspy-mcp.dll --binary app.dll --list-types
              dotnet dnspy-mcp.dll --binary app.exe --method Decrypt --json
              dotnet dnspy-mcp.dll --binary app.dll --inspect System.String --json
              dotnet dnspy-mcp.dll --binary app.dll --method Decrypt -o results.json --json

            DEPLOYMENT:
              Use dnspy-mcp-deploy for automated setup and configuration.
              See README.md for detailed installation instructions.
            """);
    }
}

class CliOptions
{
    public string? BinaryPath { get; set; }
    public string? Method { get; set; }
    public string? Type { get; set; }
    public string? OutputPath { get; set; }
    public string? InspectType { get; set; }
    public bool JsonOutput { get; set; }
    public bool ListTypes { get; set; }
    public bool ListMethods { get; set; }
}
