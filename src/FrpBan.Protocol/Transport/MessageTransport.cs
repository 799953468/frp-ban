using System.Buffers;
using System.Buffers.Binary;

namespace FrpBan.Protocol.Transport;

/// <summary>Reads bounded protocol frames independently of TCP packet boundaries.</summary>
public static class MessageTransport
{
    /// <summary>Reads one complete frame, or null when the peer closes between frames.</summary>
    /// <param name="stream">The authenticated transport stream.</param>
    /// <param name="cancellationToken">Cancels all reads for this frame.</param>
    /// <returns>The next message; null indicates a clean end of stream.</returns>
    public static async ValueTask<Message?> ReadAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        var header = new byte[5];
        if (await stream.ReadAsync(header.AsMemory(0, 1), cancellationToken).ConfigureAwait(false) == 0)
            return null;

        await stream.ReadExactlyAsync(header.AsMemory(1), cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1));
        if (length > Message.MaxBodySize)
            throw new InvalidDataException("Protocol message exceeds the maximum body size.");
        if (!Enum.IsDefined((MessageType)header[0]))
            throw new InvalidDataException("Unknown protocol message type.");

        var frameLength = checked((int)length + header.Length);
        var buffer = ArrayPool<byte>.Shared.Rent(frameLength);
        try
        {
            header.CopyTo(buffer, 0);
            await stream.ReadExactlyAsync(buffer.AsMemory(header.Length, (int)length), cancellationToken)
                .ConfigureAwait(false);
            return Message.Deserialize(buffer.AsSpan(0, frameLength)).message;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }
}
