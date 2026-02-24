using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;
using DnSpyMcp.Core;
using DnSpyMcp.Tools.Analysis;
using DnSpyMcp.Tools.Security;

var builder = Host.CreateApplicationBuilder(args);


builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Logging.ClearProviders();

builder.Services.AddSingleton<AssemblyCache>();
builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithToolsFromAssembly();

await builder.Build().RunAsync();
