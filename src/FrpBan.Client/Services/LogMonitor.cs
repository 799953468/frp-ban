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

/// <summary>
/// File-based log monitoring (tail -f style).
/// </summary>
public sealed class FileLogMonitor : LogMonitor
{
    public FileLogMonitor(
        ILogger logger,
        BanRule rule,
        RuleMatchEngine matchEngine,
        Func<List<(string ip, int? durationSeconds, string reason)>, Task> onMatches)
        : base(logger, rule, matchEngine, onMatches)
    {
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        var path = _rule.LogSource.Path;
        if (string.IsNullOrWhiteSpace(path))
        {
            _logger.LogError("Rule '{Rule}': file log source requires 'Path' setting", _rule.Name);
            return;
        }

        _logger.LogInformation("Rule '{Rule}': monitoring file {Path}", _rule.Name, path);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (!File.Exists(path))
                {
                    await Task.Delay(5000, cancellationToken);
                    continue;
                }

                // Read file from end
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var reader = new StreamReader(stream))
                {
                    // Start from end
                    stream.Seek(0, SeekOrigin.End);

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        var line = await reader.ReadLineAsync();
                        if (line != null)
                        {
                            await ProcessLineAsync(line);
                        }
                        else
                        {
                            // No new lines, wait before checking again
                            await Task.Delay(100, cancellationToken);
                        }
                    }
                }
            }
            catch (FileNotFoundException)
            {
                _logger.LogWarning("Log file not found: {Path}", path);
                await Task.Delay(5000, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error monitoring file {Path}", path);
                await Task.Delay(5000, cancellationToken);
            }
        }
    }

    private async Task ProcessLineAsync(string line)
    {
        var matches = _matchEngine.ProcessLogLine(line, _rule);
        if (matches.Count > 0)
        {
            await _onMatches(matches);
        }
    }
}

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
