using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog;

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------

var config = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
    .AddEnvironmentVariables()
    .Build();

var clientSettings = config.GetSection("ClientSettings").Get<ClientSettings>() ?? new ClientSettings();

// -------------------------------------------------------------------------
// Logging
// -------------------------------------------------------------------------

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

// -------------------------------------------------------------------------
// DI Container
// -------------------------------------------------------------------------

var services = new ServiceCollection();
services.AddLogging(builder => builder.AddSerilog());
services.AddSingleton(Options.Create(clientSettings));
services.AddSingleton<ClientConnectionService>();
services.AddSingleton<RuleMatchEngine>();
services.AddSingleton<RulesLoader>();

var serviceProvider = services.BuildServiceProvider();

// -------------------------------------------------------------------------
// Main Application Logic
// -------------------------------------------------------------------------

var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
var connectionService = serviceProvider.GetRequiredService<ClientConnectionService>();
var ruleMatchEngine = serviceProvider.GetRequiredService<RuleMatchEngine>();
var rulesLoader = serviceProvider.GetRequiredService<RulesLoader>();

logger.LogInformation("FrpBan Client started");
logger.LogInformation("Server: {Server}:{Port}", clientSettings.ServerAddress, clientSettings.ServerPort);

// Load rules
var rules = rulesLoader.LoadRules(clientSettings.RulesPath);

// Handle graceful shutdown
var cts = new CancellationTokenSource();
Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    logger.LogInformation("Shutdown signal received");
    cts.Cancel();
};

try
{
    // Connection loop with rule monitoring
    await Task.Run(async () =>
    {
        var logMonitors = new Dictionary<BanRule, LogMonitor>();

        while (!cts.Token.IsCancellationRequested)
        {
            try
            {
                // Connect
                if (!connectionService.IsConnected)
                {
                    logger.LogInformation("Connecting to server...");
                    var connected = await connectionService.ConnectAsync(cts.Token);
                    if (!connected)
                    {
                        await connectionService.WaitBeforeRetryAsync(cts.Token);
                        continue;
                    }

                    // Start log monitors once connected
                    if (logMonitors.Count == 0 && rules.Count > 0)
                    {
                        logger.LogInformation("Starting {Count} log monitor(s)", rules.Count);
                        foreach (var rule in rules)
                        {
                            if (rule.Enabled)
                            {
                                async Task OnMatches(List<(string ip, int? duration, string reason)> matches)
                                {
                                    foreach (var (ip, duration, reason) in matches)
                                    {
                                        logger.LogInformation("Ban triggered: IP={IP}, Rule={Rule}", ip, rule.Name);
                                        await connectionService.SendBanRequestAsync(ip, reason, duration, cts.Token);
                                    }
                                }

                                var monitor = LogMonitor.Create(rule, ruleMatchEngine, OnMatches, serviceProvider.GetRequiredService<ILogger<LogMonitor>>());
                                _ = monitor.StartAsync(cts.Token); // Start monitoring in background
                                logMonitors[rule] = monitor;
                            }
                        }
                    }
                }

                // Keep connection alive with health checks
                while (connectionService.IsConnected && !cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(clientSettings.Reconnection.HealthCheckIntervalMs, cts.Token);
                    var pingResult = await connectionService.SendPingAsync(cts.Token);
                    if (!pingResult)
                    {
                        logger.LogWarning("Health check failed, will reconnect...");
                        connectionService.Disconnect();
                    }
                }

                if (!connectionService.IsConnected)
                {
                    logger.LogWarning("Connection lost, will reconnect...");
                    await connectionService.WaitBeforeRetryAsync(cts.Token);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error in connection loop");
                connectionService.Disconnect();
                await connectionService.WaitBeforeRetryAsync(cts.Token);
            }
        }
    }, cts.Token);
}
catch (OperationCanceledException)
{
    // Expected during shutdown
}
catch (Exception ex)
{
    logger.LogError(ex, "Fatal error");
    Environment.Exit(1);
}
finally
{
    connectionService.Disconnect();
    logger.LogInformation("FrpBan Client stopped");
    await Log.CloseAndFlushAsync();
}
