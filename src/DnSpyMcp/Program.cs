using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;
using DnSpyMcp.Core;
using DnSpyMcp.Tools.Analysis;
using DnSpyMcp.Tools.Security;

var builder = Host.CreateApplicationBuilder(args);

if (Environment.GetEnvironmentVariable("WAIT_FOR_DEBUGGER") == "1")
{
    Console.Error.WriteLine($"[dnspy-mcp] Waiting for debugger. PID={Environment.ProcessId}");
    Console.Error.WriteLine($"[dnspy-mcp] Attach with: vsdbg, lldb, or VS Code .NET attach");
    while (!System.Diagnostics.Debugger.IsAttached)
        await Task.Delay(500);
    Console.Error.WriteLine("[dnspy-mcp] Debugger attached.");
    System.Diagnostics.Debugger.Break();
}

builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Logging.ClearProviders();

builder.Services.AddSingleton<AssemblyCache>();
builder.Services.AddSingleton<BreakpointRegistry>();
builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithToolsFromAssembly();

await builder.Build().RunAsync();
