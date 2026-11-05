using System.Text.Json.Serialization;

namespace FrpBan.Models;

// ---------------------------------------------------------------------------
// Inbound request from frps
// ---------------------------------------------------------------------------

/// <summary>
/// Top-level request envelope sent by frps to the plugin HTTP server.
/// </summary>
public sealed record PluginRequest(
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("op")]      string Op,
    [property: JsonPropertyName("content")] System.Text.Json.JsonElement Content
);

/// <summary>
/// The "user" block present on every operation except Login.
/// </summary>
public sealed record FrpUser(
    [property: JsonPropertyName("user")]    string User,
    [property: JsonPropertyName("run_id")]  string RunId,
    [property: JsonPropertyName("metas")]   Dictionary<string, string>? Metas
);

/// <summary>
/// Content payload for the Login operation.
/// </summary>
public sealed record LoginContent(
    [property: JsonPropertyName("version")]        string Version,
    [property: JsonPropertyName("client_address")] string ClientAddress,
    [property: JsonPropertyName("user")]           string User,
    [property: JsonPropertyName("run_id")]         string RunId,
    [property: JsonPropertyName("metas")]          Dictionary<string, string>? Metas,
    [property: JsonPropertyName("timestamp")]      long Timestamp,
    [property: JsonPropertyName("privilege_key")]  string PrivilegeKey
);

/// <summary>
/// Content payload for the NewUserConn operation — fires when an end-user
/// connects to a proxy. remote_addr is the user's IP:port.
/// </summary>
public sealed record NewUserConnContent(
    [property: JsonPropertyName("user")]        FrpUser User,
    [property: JsonPropertyName("proxy_name")]  string ProxyName,
    [property: JsonPropertyName("proxy_type")]  string ProxyType,
    [property: JsonPropertyName("remote_addr")] string RemoteAddr
);

// ---------------------------------------------------------------------------
// Outbound response to frps
// ---------------------------------------------------------------------------

/// <summary>
/// Response envelope returned to frps after handling a plugin operation.
/// </summary>
public sealed record PluginResponse(
    [property: JsonPropertyName("reject")]        bool Reject,
    [property: JsonPropertyName("reject_reason")] string? RejectReason = null,
    [property: JsonPropertyName("unchange")]      bool Unchange = true
)
{
    /// <summary>Allow the operation without modifying its content.</summary>
    public static readonly PluginResponse Allow = new(false, null, true);

    /// <summary>Creates a rejection response with the given reason.</summary>
    public static PluginResponse Deny(string reason) => new(true, reason, false);
}
