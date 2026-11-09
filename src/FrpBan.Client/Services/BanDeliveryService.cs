using System.Threading.Channels;
using FrpBan.Client.Configuration;
using FrpBan.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FrpBan.Client.Services;

/// <summary>Buffers pending bans with bounded memory and retries delivery after a reconnect.</summary>
public sealed class BanDeliveryService
{
    private readonly ClientConnectionService _connection;
    private readonly ILogger<BanDeliveryService> _logger;
    private readonly Channel<BanRequestMessage> _pending;

    /// <summary>Creates a single-consumer delivery queue with backpressure.</summary>
    public BanDeliveryService(ClientConnectionService connection, IOptions<ClientSettings> settings,
        ILogger<BanDeliveryService> logger)
    {
        _connection = connection;
        _logger = logger;
        _pending = Channel.CreateBounded<BanRequestMessage>(new BoundedChannelOptions(settings.Value.MaxPendingBans)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
    }

    /// <summary>Queues a ban, waiting when the configured memory budget is full.</summary>
    public ValueTask EnqueueAsync(string ip, string reason, int? durationSeconds, CancellationToken cancellationToken) =>
        _pending.Writer.WriteAsync(new BanRequestMessage(ip, reason, durationSeconds), cancellationToken);

    /// <summary>Delivers queued bans until shutdown, retaining the current ban across transport failures.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        await foreach (var ban in _pending.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (!_connection.IsConnected)
                {
                    await Task.Delay(250, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                if (await _connection.SendBanRequestAsync(ban.Ip, ban.Reason, ban.DurationSeconds, cancellationToken)
                        .ConfigureAwait(false))
                    break;
                if (_connection.IsConnected)
                {
                    // A negative BAN_RESPONSE is a terminal rejection; do not block the queue forever.
                    _logger.LogWarning("Server rejected queued ban for {Ip}", ban.Ip);
                    break;
                }
            }
        }
    }
}
