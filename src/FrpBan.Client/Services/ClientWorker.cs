using FrpBan.Client.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FrpBan.Client.Services;

/// <summary>
/// Runs the client: log monitors, the ban delivery queue, and the connection supervisor.
/// Monitors start immediately so attacks during a server outage are queued rather than missed.
/// If any component fails, or reconnection attempts run out, the process exits with code 1
/// so the service manager can restart it.
/// </summary>
public sealed class ClientWorker(
    IOptions<ClientSettings> settings,
    RulesLoader rulesLoader,
    RuleMatchEngine matchEngine,
    ClientConnectionService connection,
    BanDeliveryService delivery,
    ILoggerFactory loggerFactory,
    IHostApplicationLifetime lifetime,
    ILogger<ClientWorker> logger) : BackgroundService
{
    private readonly ClientSettings _settings = settings.Value;

    /// <inheritdoc/>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Client stopped due to an error");
            Environment.ExitCode = 1;
            lifetime.StopApplication();
        }
    }

    private async Task RunAsync(CancellationToken stoppingToken)
    {
        var rules = rulesLoader.LoadRules(_settings.RulesPath).Where(rule => rule.Enabled).ToList();
        if (rules.Count == 0)
            throw new InvalidOperationException("No valid enabled rules were loaded.");

        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var monitorLogger = loggerFactory.CreateLogger<LogMonitor>();
        var components = new List<Task>
        {
            delivery.RunAsync(stopping.Token),
            SuperviseConnectionAsync(stopping.Token),
        };
        components.AddRange(rules.Select(rule => LogMonitor.Create(rule, matchEngine, EnqueueAsync, monitorLogger)
            .StartAsync(stopping.Token)));

        var first = await Task.WhenAny(components).ConfigureAwait(false);
        try
        {
            await first.ConfigureAwait(false);
            stoppingToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException("A client component stopped unexpectedly.");
        }
        finally
        {
            await stopping.CancelAsync().ConfigureAwait(false);
            await DrainAsync(components.Where(component => component != first)).ConfigureAwait(false);
        }

        async Task EnqueueAsync(IReadOnlyList<BanMatch> matches)
        {
            foreach (var match in matches)
                await delivery.EnqueueAsync(match, stopping.Token).ConfigureAwait(false);
        }
    }

    /// <summary>Connects, health-checks with PING, and reconnects with backoff until retries run out.</summary>
    private async Task SuperviseConnectionAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!connection.IsConnected && !await connection.ConnectAsync(cancellationToken).ConfigureAwait(false))
            {
                await WaitBeforeRetryAsync(cancellationToken).ConfigureAwait(false);
                continue;
            }

            await Task.Delay(_settings.Reconnection.HealthCheckIntervalMs, cancellationToken).ConfigureAwait(false);
            if (!await connection.SendPingAsync(cancellationToken).ConfigureAwait(false))
            {
                connection.Disconnect();
                await WaitBeforeRetryAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task WaitBeforeRetryAsync(CancellationToken cancellationToken)
    {
        if (!await connection.WaitBeforeRetryAsync(cancellationToken).ConfigureAwait(false))
            throw new InvalidOperationException("Maximum reconnection attempts reached.");
    }

    private async Task DrainAsync(IEnumerable<Task> components)
    {
        foreach (var component in components)
        {
            try
            {
                await component.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Client component failed during shutdown");
            }
        }
    }
}
