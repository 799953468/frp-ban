using System.Text;
using System.Threading.Channels;
using FrpBan.Client.Matching;
using Microsoft.Extensions.Logging;

namespace FrpBan.Client.Services;

/// <summary>Processes coalesced file notifications in one worker, retaining partial UTF-8 lines.</summary>
public sealed class FileLogMonitor(
    ILogger logger, CompiledRule rule, RuleMatchEngine matchEngine,
    Func<IReadOnlyList<BanMatch>, Task> onMatches)
    : LogMonitor(logger, rule, matchEngine, onMatches)
{
    private readonly Channel<byte> _notifications = Channel.CreateBounded<byte>(new BoundedChannelOptions(1)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.DropWrite,
    });
    private int _reset;

    /// <inheritdoc/>
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        var path = Path.GetFullPath(_rule.Definition.LogSource.Path ??
                                    throw new InvalidOperationException("Log path is required."));
        var initialPosition = File.Exists(path) ? new FileInfo(path).Length : 0;
        using var watcher = new FileSystemWatcher(Path.GetDirectoryName(path)!, Path.GetFileName(path))
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
        };
        watcher.Changed += (_, _) => Signal(reset: false);
        watcher.Created += (_, _) => Signal(reset: true);
        watcher.Deleted += (_, _) => Signal(reset: true, force: true);
        watcher.Renamed += (_, _) => Signal(reset: true, force: true);
        watcher.Error += (_, args) =>
        {
            _logger.LogWarning(args.GetException(), "Log watcher overflow/error for {Path}; rescanning", path);
            Signal(reset: true, force: true);
        };
        watcher.EnableRaisingEvents = true;

        FileStream? stream = null;
        var lines = new LineAccumulator(RuleMatchEngine.MaxLogLineLength,
            () => _logger.LogWarning("Discarding oversized log line in {Path}", path));
        var creationTime = DateTime.MinValue;
        var bytes = new byte[4096];
        var characters = new char[Encoding.UTF8.GetMaxCharCount(bytes.Length)];
        var decoder = Encoding.UTF8.GetDecoder();
        var position = initialPosition;
        var atBeginning = position == 0;
        Signal(reset: false);
        try
        {
            while (await _notifications.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (_notifications.Reader.TryRead(out _)) { }
                try
                {
                    var notification = Interlocked.Exchange(ref _reset, 0);
                    // macOS may replay a Created flag on a later Changed notification.
                    // Reopen for Created only when it identifies a different file.
                    var reset = notification != 0 && (stream is null || (notification & 2) != 0 ||
                        File.GetCreationTimeUtc(path) != creationTime);
                    if (reset || stream is not null && stream.Length < stream.Position)
                    {
                        stream?.Dispose();
                        stream = null;
                        lines.Reset();
                        position = 0;
                        atBeginning = true;
                        decoder.Reset();
                    }

                    if (stream is null)
                    {
                        stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                            4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
                        creationTime = File.GetCreationTimeUtc(path);
                        stream.Seek(Math.Min(position, stream.Length), SeekOrigin.Begin);
                    }

                    int count;
                    while ((count = await stream.ReadAsync(bytes.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
                    {
                        position = stream.Position;
                        // EOF is temporary for a tailer: never flush a partially received UTF-8 character.
                        var characterCount = decoder.GetChars(bytes, 0, count, characters, 0, flush: false);
                        for (var i = 0; i < characterCount; i++)
                        {
                            var character = characters[i];
                            if (atBeginning)
                            {
                                atBeginning = false;
                                if (character == '\uFEFF') continue;
                            }

                            if (lines.Append(character) is { } line)
                                await ProcessLineAsync(line).ConfigureAwait(false);
                        }
                    }
                }
                catch (IOException ex)
                {
                    _logger.LogDebug(ex, "Transient error tailing {Path}", path);
                    stream?.Dispose();
                    stream = null;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally
        {
            stream?.Dispose();
        }
    }

    private void Signal(bool reset, bool force = false)
    {
        if (reset) Interlocked.Or(ref _reset, force ? 2 : 1);
        _notifications.Writer.TryWrite(0);
    }
}
