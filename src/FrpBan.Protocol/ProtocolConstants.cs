namespace FrpBan.Protocol;

/// <summary>Values both peers must agree on.</summary>
public static class ProtocolConstants
{
    /// <summary>Protocol version exchanged in HELLO. Peers with a different version are rejected.</summary>
    public const string Version = "2.0";

    /// <summary>The ClientType the server announces in its HELLO reply.</summary>
    public const string ServerClientType = "server";

    /// <summary>The ClientType the log-monitoring client announces in its HELLO.</summary>
    public const string ClientClientType = "frp-ban-client";

    /// <summary>Maximum ban reason length in characters, enforced by the server.</summary>
    public const int MaxReasonLength = 1024;
}
