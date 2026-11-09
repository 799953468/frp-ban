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
/// File-based log monitoring using FileSystemWatcher for efficient change detection.
/// PERFORMANCE: Uses FileSystemWatcher instead of polling, significantly reduces CPU usage.
/// </summary>
public sealed class FileLogMonitor : LogMonitor
{
    private FileSystemWatcher? _watcher;
    private long _lastPosition;

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

        var directory = Path.GetDirectoryName(path);
        var fileName = Path.GetFileName(path);

        if (string.IsNullOrEmpty(directory) || string.IsNullOrEmpty(fileName))
        {
            _logger.LogError("Rule '{Rule}': invalid file path {Path}", _rule.Name, path);
            return;
        }

        _logger.LogInformation("Rule '{Rule}': monitoring file {Path} (using FileSystemWatcher)", _rule.Name, path);

        // Get initial file size
        if (File.Exists(path))
        {
            _lastPosition = new FileInfo(path).Length;
        }

        // Set up FileSystemWatcher
        _watcher = new FileSystemWatcher(directory, fileName)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
            EnableRaisingEvents = true
        };

        _watcher.Changed += async (sender, e) => await OnFileChangedAsync(e.FullPath, cancellationToken);
        _watcher.Created += async (sender, e) =>
        {
            _lastPosition = 0;
            await OnFileChangedAsync(e.FullPath, cancellationToken);
        };

        // Keep task alive
        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Expected during shutdown
        }
        finally
        {
            _watcher?.Dispose();
        }
    }

    private async Task OnFileChangedAsync(string filePath, CancellationToken cancellationToken)
    {
        try
        {
            // Wait a bit for file to be fully written
            await Task.Delay(50, cancellationToken);

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            if (stream.Length <= _lastPosition)
            {
                // File was truncated/rotated
                _lastPosition = 0;
            }

            stream.Seek(_lastPosition, SeekOrigin.Begin);
            using var reader = new StreamReader(stream);

            string? line;
            while ((line = await reader.ReadLineAsync(cancellationToken)) != null)
            {
                await ProcessLineAsync(line);
            }

            _lastPosition = stream.Position;
        }
        catch (IOException ex)
        {
            _logger.LogDebug(ex, "Transient I/O error reading {Path}", filePath);
        }
        catch (OperationCanceledException)
        {
            // Expected
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing file changes {Path}", filePath);
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
