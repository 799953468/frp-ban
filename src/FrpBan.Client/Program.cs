using System.ComponentModel.DataAnnotations;
using System.Runtime.InteropServices;
using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog;

var config = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false)
    .AddEnvironmentVariables()
    .Build();
var settings = config.GetSection("ClientSettings").Get<ClientSettings>() ?? new ClientSettings();
var logging = new LoggerConfiguration().MinimumLevel.Information().Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}");
if (!string.IsNullOrWhiteSpace(settings.AppLogPath))
{
    logging.WriteTo.File(settings.AppLogPath, rollingInterval: RollingInterval.Day,
        rollOnFileSizeLimit: true, fileSizeLimitBytes: 104857600, retainedFileCountLimit: 30);
}

Log.Logger = logging.CreateLogger();

var services = new ServiceCollection();
services.AddLogging(builder => builder.AddSerilog());
services.AddSingleton(Options.Create(settings));
services.AddSingleton<ClientConnectionService>();
services.AddSingleton<BanDeliveryService>();
services.AddSingleton<RuleMatchEngine>();
services.AddSingleton<RulesLoader>();
await using var provider = services.BuildServiceProvider();
using var stopping = new CancellationTokenSource();
var logger = provider.GetRequiredService<ILogger<Program>>();
ClientConnectionService? connection = null;
var monitorTasks = new List<Task>();
var exitCode = 0;
ConsoleCancelEventHandler cancel = (_, args) =>
{
    args.Cancel = true;
    stopping.Cancel();
};
Console.CancelKeyPress += cancel;
using var termination = OperatingSystem.IsWindows()
    ? null
    : PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
    {
        context.Cancel = true;
        stopping.Cancel();
    });

try
{
    foreach (var error in settings.Validate())
    {
        throw new ValidationException(error.ErrorMessage);
    }

    connection = provider.GetRequiredService<ClientConnectionService>();
    var rules = provider.GetRequiredService<RulesLoader>().LoadRules(settings.RulesPath)
        .Where(rule => rule.Enabled).ToList();
    if (rules.Count == 0)
    {
        throw new InvalidOperationException("No valid enabled rules were loaded.");
    }

    var engine = provider.GetRequiredService<RuleMatchEngine>();
    var delivery = provider.GetRequiredService<BanDeliveryService>();
    monitorTasks.Add(delivery.RunAsync(stopping.Token));
    var monitorsStarted = false;

    while (!stopping.IsCancellationRequested)
    {
        if (!connection.IsConnected)
        {
            if (!await connection.ConnectAsync(stopping.Token))
            {
                if (!await connection.WaitBeforeRetryAsync(stopping.Token))
                {
                    exitCode = 1;
                    break;
                }

                continue;
            }

            if (!monitorsStarted)
            {
                foreach (var rule in rules)
                {
                    async Task OnMatches(List<(string ip, int? duration, string reason)> matches)
                    {
                        foreach (var (ip, duration, reason) in matches)
                        {
                            await delivery.EnqueueAsync(ip, reason, duration, stopping.Token);
                        }
                    }

                    var monitor = LogMonitor.Create(rule, engine, OnMatches,
                        provider.GetRequiredService<ILogger<LogMonitor>>());
                    monitorTasks.Add(monitor.StartAsync(stopping.Token));
                }

                monitorsStarted = true;
            }
        }

        var healthDelay = Task.Delay(settings.Reconnection.HealthCheckIntervalMs, stopping.Token);
        var completed = await Task.WhenAny(monitorTasks.Append(healthDelay));
        if (completed != healthDelay)
        {
            await completed;
            throw new InvalidOperationException("A log monitor stopped unexpectedly.");
        }

        await healthDelay;
        if (!await connection.SendPingAsync(stopping.Token))
        {
            connection.Disconnect();
            if (!await connection.WaitBeforeRetryAsync(stopping.Token))
            {
                exitCode = 1;
                break;
            }
        }
    }
}
catch (OperationCanceledException) when (stopping.IsCancellationRequested)
{
}
catch (Exception ex)
{
    logger.LogError(ex, "Client stopped due to an error");
    exitCode = 1;
}
finally
{
    await stopping.CancelAsync();
    connection?.Disconnect();
    try
    {
        await Task.WhenAll(monitorTasks);
    }
    catch (OperationCanceledException)
    {
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Log monitor failed");
        exitCode = 1;
    }

    Console.CancelKeyPress -= cancel;
    logger.LogInformation("FrpBan client stopped");
    await Log.CloseAndFlushAsync();
}

return exitCode;