namespace FrpBan.Protocol;

/// <summary>
/// Message type identifiers for TLS binary protocol.
/// </summary>
public enum MessageType : byte
{
    /// <summary>
    /// Handshake message (client -> server).
    /// Body: JSON with version, clientType, tokenHash
    /// </summary>
    Hello = 0x01,

    /// <summary>
    /// Ban request message (client -> server).
    /// Body: JSON with ip, reason, durationSeconds
    /// </summary>
    BanRequest = 0x02,

    /// <summary>
    /// Ban response message (server -> client).
    /// Body: JSON with success, message
    /// </summary>
    BanResponse = 0x03,

    /// <summary>
    /// Health check ping message (client -> server).
    /// Body: empty or optional sequence number
    /// </summary>
    Ping = 0x04,

    /// <summary>
    /// Health check pong response (server -> client).
    /// Body: empty or matches ping sequence number
    /// </summary>
    Pong = 0x05,

    /// <summary>
    /// Error/disconnect message (either direction).
    /// Body: JSON with error message
    /// </summary>
    Error = 0x06,
}
