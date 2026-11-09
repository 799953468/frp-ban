using FrpBan.Client.Configuration;
using Microsoft.Extensions.Logging;

namespace FrpBan.Client.Services;

/// <summary>
/// Abstract base for log monitoring.
/// </summary>
public abstract class LogMonitor
{
    protected readonly ILogger _logger;
    protected readonly BanRule _rule;
    protected readonly RuleMatchEngine _matchEngine;
    protected readonly Func<List<(string ip, int? durationSeconds, string reason)>, Task> _onMatches;

    protected LogMonitor(
        ILogger logger,
        BanRule rule,
        RuleMatchEngine matchEngine,
        Func<List<(string ip, int? durationSeconds, string reason)>, Task> onMatches)
    {
        _logger = logger;
        _rule = rule;
        _matchEngine = matchEngine;
        _onMatches = onMatches;
    }

    /// <summary>
    /// Start monitoring logs.
    /// </summary>
    public abstract Task StartAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Factory method to create appropriate monitor based on rule's log source.
    /// </summary>
    public static LogMonitor Create(
        BanRule rule,
        RuleMatchEngine matchEngine,
        Func<List<(string ip, int? durationSeconds, string reason)>, Task> onMatches,
        ILogger logger)
    {
        return rule.LogSource.Type switch
        {
            "file" => new FileLogMonitor(logger, rule, matchEngine, onMatches),
            "journal" => new JournalLogMonitor(logger, rule, matchEngine, onMatches),
            _ => throw new InvalidOperationException($"Unknown log source type: {rule.LogSource.Type}"),
        };
    }
}
