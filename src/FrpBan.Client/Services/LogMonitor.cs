using FrpBan.Client.Matching;
using Microsoft.Extensions.Logging;

namespace FrpBan.Client.Services;

/// <summary>Reads complete lines from one log source and hands rule matches to a callback.</summary>
public abstract class LogMonitor
{
    protected readonly ILogger _logger;
    protected readonly CompiledRule _rule;
    protected readonly RuleMatchEngine _matchEngine;
    protected readonly Func<IReadOnlyList<BanMatch>, Task> _onMatches;

    protected LogMonitor(
        ILogger logger,
        CompiledRule rule,
        RuleMatchEngine matchEngine,
        Func<IReadOnlyList<BanMatch>, Task> onMatches)
    {
        _logger = logger;
        _rule = rule;
        _matchEngine = matchEngine;
        _onMatches = onMatches;
    }

    /// <summary>Monitors until cancelled. Any other completion means the monitor failed.</summary>
    public abstract Task StartAsync(CancellationToken cancellationToken);

    /// <summary>Creates the monitor for the rule's log source.</summary>
    public static LogMonitor Create(
        CompiledRule rule,
        RuleMatchEngine matchEngine,
        Func<IReadOnlyList<BanMatch>, Task> onMatches,
        ILogger logger)
    {
        return rule.SourceKind switch
        {
            LogSourceKind.File => new FileLogMonitor(logger, rule, matchEngine, onMatches),
            LogSourceKind.Journal => new JournalLogMonitor(logger, rule, matchEngine, onMatches),
            _ => throw new InvalidOperationException($"Unknown log source kind: {rule.SourceKind}"),
        };
    }

    /// <summary>Matches one complete line and delivers any resulting bans.</summary>
    protected async Task ProcessLineAsync(string line)
    {
        var matches = _matchEngine.ProcessLogLine(line, _rule);
        if (matches.Count > 0)
            await _onMatches(matches).ConfigureAwait(false);
    }
}
