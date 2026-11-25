using System.Threading.Channels;
using FrpBan.Client.Configuration;
using FrpBan.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FrpBan.Client.Services;

/// <summary>Buffers pending bans with bounded memory and delivers them in order once connected.</summary>
public sealed class BanDeliveryService
{
    private readonly ClientConnectionService _connection;
    private readonly ILogger<BanDeliveryService> _logger;
    private readonly Channel<BanRequestMessage> _pending;
    private readonly TimeSpan _retryDelay;

    /// <summary>Creates a single-consumer delivery queue with backpressure.</summary>
    public BanDeliveryService(ClientConnectionService connection, IOptions<ClientSettings> settings,
        ILogger<BanDeliveryService> logger)
    {
        _connection = connection;
        _logger = logger;
        _retryDelay = TimeSpan.FromMilliseconds(settings.Value.Reconnection.InitialDelayMs);
        _pending = Channel.CreateBounded<BanRequestMessage>(new BoundedChannelOptions(settings.Value.MaxPendingBans)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
    }

    /// <summary>Queues a ban, waiting when the configured memory budget is full.</summary>
    public ValueTask EnqueueAsync(BanMatch match, CancellationToken cancellationToken) =>
        _pending.Writer.WriteAsync(new BanRequestMessage(match.Ip, match.Reason, match.DurationSeconds), cancellationToken);

    /// <summary>
    /// Delivers queued bans until shutdown. A ban stays at the head of the queue across transport
    /// failures and retryable server statuses; terminal statuses (exempt, invalid, capacity) drop it.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        await foreach (var ban in _pending.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            while (true)
            {
                if (!_connection.IsConnected)
                {
                    await Task.Delay(250, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                var status = await _connection.SendBanRequestAsync(ban, cancellationToken).ConfigureAwait(false);
                if (status is null)
                    continue;
                if (status.Value.IsRetryable())
                {
                    await Task.Delay(_retryDelay, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                if (!status.Value.IsSuccess())
                    _logger.LogWarning("Dropping queued ban for {Ip}: server returned {Status}", ban.Ip, status);
                break;
            }
        }
    }
}
