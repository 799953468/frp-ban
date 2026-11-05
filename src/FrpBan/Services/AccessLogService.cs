using FrpBan.Configuration;
using Microsoft.Extensions.Options;

namespace FrpBan.Services;

/// <summary>
/// Appends one-line log entries to a rotating log file for fail2ban to monitor.
/// Format: <c>YYYY-MM-DD HH:MM:SS [LEVEL] MESSAGE from IP</c>
/// </summary>
public sealed class AccessLogService(
    IOptions<PluginSettings> settings,
    ILogger<AccessLogService> logger) : IAccessLogService
{
    private readonly string _logPath = settings.Value.AccessLogPath;
    // Serialise writes from concurrent requests.
    private readonly SemaphoreSlim _writeLock = new(1, 1);

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

        // Fire-and-forget; failures are surfaced via the structured logger only.
        _ = Task.Run(async () =>
        {
            await _writeLock.WaitAsync();
            try
            {
                var dir = Path.GetDirectoryName(_logPath);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                await File.AppendAllTextAsync(_logPath, line + Environment.NewLine);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to write access log entry to {Path}", _logPath);
            }
            finally { _writeLock.Release(); }
        });
    }
}
