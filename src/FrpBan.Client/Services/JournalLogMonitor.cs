using FrpBan.Client.Configuration;
using Microsoft.Extensions.Logging;

namespace FrpBan.Client.Services;

/// <summary>
/// Systemd journal monitoring.
/// </summary>
public sealed class JournalLogMonitor : LogMonitor
{
    public JournalLogMonitor(
        ILogger logger,
        BanRule rule,
        RuleMatchEngine matchEngine,
        Func<List<(string ip, int? durationSeconds, string reason)>, Task> onMatches)
        : base(logger, rule, matchEngine, onMatches)
    {
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogWarning("Rule '{Rule}': journal monitoring not yet implemented", _rule.Name);
        // TODO: Implement systemd journal monitoring using System.Diagnostics or journalctl
        await Task.CompletedTask;
    }
}
