using FrpBan.Configuration;
using Microsoft.Extensions.Options;

namespace FrpBan.Services;

/// <summary>
/// Appends one-line log entries to a rotating log file for fail2ban to monitor.
/// Format: <c>YYYY-MM-DD HH:MM:SS [LEVEL] MESSAGE from IP</c>
/// </summary>
public sealed class AccessLogService : IAccessLogService, IDisposable
{
    private readonly string _logPath;
    private readonly ILogger<AccessLogService> _logger;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private FileStream? _fileStream;
    private StreamWriter? _writer;

    public AccessLogService(IOptions<PluginSettings> settings, ILogger<AccessLogService> logger)
    {
        _logPath = settings.Value.AccessLogPath;
        _logger = logger;
    }

    /// <inheritdoc/>
    public void LogUnauthorized(string remoteIp, string path, string method)
    {
        // This line format is what the fail2ban filter regex targets.
        Write($"[WARN] Unauthorized {method} {path} from {remoteIp}");
    }

    /// <inheritdoc/>
    public void LogBanAction(string remoteIp, string action, string targetIp)
    {
        Write($"[INFO] {action} {targetIp} by {remoteIp}");
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void Write(string message)
    {
        var line = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} {message}";

        // Queue write operation
        _ = Task.Run(async () =>
        {
            await _writeLock.WaitAsync();
            try
            {
                await EnsureWriterAsync();

                if (_writer is not null)
                {
                    await _writer.WriteLineAsync(line);
                    await _writer.FlushAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write access log entry to {Path}", _logPath);

                // Try to recreate the writer on next attempt
                CloseWriter();
            }
            finally { _writeLock.Release(); }
        });
    }

    private async Task EnsureWriterAsync()
    {
        if (_writer is not null)
            return;

        var dir = Path.GetDirectoryName(_logPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        _fileStream = new FileStream(_logPath, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, useAsync: true);
        _writer = new StreamWriter(_fileStream, System.Text.Encoding.UTF8) { AutoFlush = false };
    }

    private void CloseWriter()
    {
        _writer?.Dispose();
        _writer = null;
        _fileStream?.Dispose();
        _fileStream = null;
    }

    public void Dispose()
    {
        _writeLock.Wait();
        try
        {
            CloseWriter();
        }
        finally
        {
            _writeLock.Release();
            _writeLock.Dispose();
        }
    }
}

