using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using FrpBan.Client.Configuration;
using Microsoft.Extensions.Logging;

namespace FrpBan.Client.Services;

/// <summary>
/// Follows new systemd journal messages for one unit using journalctl.
/// </summary>
public sealed class JournalLogMonitor : LogMonitor
{
    private const int MaxDiagnosticLength = 4096;

    /// <summary>Creates a journal monitor using the existing rule matching and ban delivery pipeline.</summary>
    /// <param name="logger">Logger for journal diagnostics.</param>
    /// <param name="rule">Rule containing the systemd unit and matching expressions.</param>
    /// <param name="matchEngine">Engine that evaluates each message line.</param>
    /// <param name="onMatches">Asynchronous callback that delivers matched bans.</param>
    public JournalLogMonitor(
        ILogger logger,
        BanRule rule,
        RuleMatchEngine matchEngine,
        Func<List<(string ip, int? durationSeconds, string reason)>, Task> onMatches)
        : base(logger, rule, matchEngine, onMatches)
    {
    }

    /// <inheritdoc/>
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Systemd journal monitoring requires Linux and journalctl.");
        }

        await MonitorProcessAsync(CreateStartInfo(), cancellationToken).ConfigureAwait(false);
    }

    internal ProcessStartInfo CreateStartInfo()
    {
        if (string.IsNullOrWhiteSpace(_rule.LogSource.Service))
        {
            throw new InvalidOperationException($"Rule '{_rule.Name}': a journal service is required.");
        }

        var startInfo = new ProcessStartInfo("journalctl")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("--follow");
        startInfo.ArgumentList.Add("--lines=0");
        startInfo.ArgumentList.Add("--output=cat");
        startInfo.ArgumentList.Add("--no-pager");
        startInfo.ArgumentList.Add("--system");
        // Keep the unit in a single option value; never interpret it as shell text or another option.
        startInfo.ArgumentList.Add($"--unit={_rule.LogSource.Service}");
        startInfo.Environment["SYSTEMD_COLORS"] = "0";
        return startInfo;
    }

    internal async Task MonitorProcessAsync(ProcessStartInfo startInfo, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using (var process = new Process())
        {
            process.StartInfo = startInfo;
            try
            {
                process.Start();
            }
            catch (Win32Exception ex)
            {
                throw new InvalidOperationException(
                    $"Rule '{_rule.Name}': could not start journalctl. Ensure it is installed and available on PATH.", ex);
            }

            using (var reading = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                // Drain stderr concurrently so diagnostics cannot fill the pipe and block journalctl.
                var diagnostics = ReadDiagnosticsAsync(process.StandardError, reading.Token);
                try
                {
                    _logger.LogInformation("Rule {Rule}: following journal messages for {Service}",
                        _rule.Name, _rule.LogSource.Service);
                    await ProcessOutputAsync(process.StandardOutput, cancellationToken).ConfigureAwait(false);
                    await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                    var lastDiagnostic = await diagnostics.ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    // Even a successful exit is unexpected for a follower. Let the client supervisor restart it.
                    throw new InvalidOperationException(
                        $"Rule '{_rule.Name}': journalctl exited unexpectedly with code {process.ExitCode}. " +
                        $"Check the unit name and journal read permissions. {lastDiagnostic}");
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                }
                finally
                {
                    await reading.CancelAsync().ConfigureAwait(false);
                    try
                    {
                        if (!process.HasExited)
                        {
                            process.Kill(entireProcessTree: true);
                        }
                    }
                    catch (InvalidOperationException)
                    {
                        // The process may exit between HasExited and Kill.
                    }

                    await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                    try
                    {
                        await diagnostics.ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (reading.IsCancellationRequested)
                    {
                    }
                }
            }
        }
    }

    internal async Task ProcessOutputAsync(TextReader reader, CancellationToken cancellationToken)
    {
        await foreach (var line in ReadLinesAsync(reader, RuleMatchEngine.MaxLogLineLength,
                           includeFinalLine: false, cancellationToken).ConfigureAwait(false))
        {
            var matches = _matchEngine.ProcessLogLine(line, _rule);
            if (matches.Count > 0)
            {
                await _onMatches(matches).ConfigureAwait(false);
            }
        }
    }

    private async Task<string?> ReadDiagnosticsAsync(TextReader reader, CancellationToken cancellationToken)
    {
        string? lastDiagnostic = null;
        await foreach (var line in ReadLinesAsync(reader, MaxDiagnosticLength,
                           includeFinalLine: true, cancellationToken).ConfigureAwait(false))
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                lastDiagnostic = line;
                _logger.LogWarning("Rule {Rule}: journalctl: {Diagnostic}", _rule.Name, line);
            }
        }

        return lastDiagnostic;
    }

    private async IAsyncEnumerable<string> ReadLinesAsync(TextReader reader, int maxLength, bool includeFinalLine,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var buffer = new char[4096];
        var line = new StringBuilder();
        var discarding = false;
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
        {
            for (var i = 0; i < count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var character = buffer[i];
                if (character == '\n')
                {
                    if (!discarding)
                    {
                        if (line.Length > 0 && line[^1] == '\r')
                        {
                            line.Length--;
                        }

                        yield return line.ToString();
                    }

                    line.Clear();
                    discarding = false;
                }
                else if (!discarding)
                {
                    // Allow a trailing CR at the limit, without retaining unbounded partial lines.
                    if (line.Length >= maxLength && !(line.Length == maxLength && character == '\r'))
                    {
                        line.Clear();
                        discarding = true;
                        _logger.LogWarning("Rule {Rule}: discarding oversized journalctl output line", _rule.Name);
                    }
                    else
                    {
                        line.Append(character);
                    }
                }
            }
        }

        // stdout records must end in a newline; never match an incomplete message after a process failure.
        if (includeFinalLine && !discarding && line.Length > 0)
        {
            yield return line.ToString();
        }
    }
}