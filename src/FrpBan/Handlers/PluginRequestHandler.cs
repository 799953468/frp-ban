using System.Net;
using System.Text.Json;
using FrpBan.Models;
using FrpBan.Protocol;
using FrpBan.Services;

namespace FrpBan.Handlers;

/// <summary>
/// Processes frps plugin callbacks and returns allow/deny decisions based on the current ban list.
/// Login and NewUserConn fail closed: malformed payloads are denied.
/// </summary>
public sealed class PluginRequestHandler(
    IBanService banService,
    ILogger<PluginRequestHandler> logger)
{
    /// <summary>Handles one frps plugin request.</summary>
    /// <param name="request">The callback envelope.</param>
    /// <param name="requestId">The X-Frp-Reqid header, for diagnostics only.</param>
    public PluginResponse Handle(PluginRequest request, string? requestId = null)
    {
        logger.LogDebug("Plugin op={Op} reqid={ReqId}", request.Op, requestId);
        try
        {
            return request.Op switch
            {
                "Login" => HandleLogin(request.Content),
                "NewUserConn" => HandleNewUserConn(request.Content),
                _ => PluginResponse.Allow,
            };
        }
        catch (JsonException)
        {
            return PluginResponse.Deny("invalid plugin payload");
        }
    }

    /// <summary>Rejects a banned frpc client before it can authenticate and register proxies.</summary>
    private PluginResponse HandleLogin(JsonElement content)
    {
        if (content.ValueKind != JsonValueKind.Object)
            return PluginResponse.Deny("invalid plugin payload");

        var login = content.Deserialize(ServerJsonContext.Default.LoginContent);
        if (ParseIp(login?.ClientAddress) is not { } ip)
            return PluginResponse.Deny("invalid client address");
        if (!banService.IsBanned(ip))
            return PluginResponse.Allow;

        logger.LogWarning("Login rejected — banned IP {Ip} (run_id={RunId})", ip, login!.RunId);
        return PluginResponse.Deny($"IP {ip} is banned");
    }

    /// <summary>Rejects a banned end user before the connection is forwarded through the tunnel.</summary>
    private PluginResponse HandleNewUserConn(JsonElement content)
    {
        if (content.ValueKind != JsonValueKind.Object)
            return PluginResponse.Deny("invalid plugin payload");

        var connection = content.Deserialize(ServerJsonContext.Default.NewUserConnContent);
        if (ParseIp(connection?.RemoteAddr) is not { } ip)
            return PluginResponse.Deny("invalid remote address");
        if (!banService.IsBanned(ip))
            return PluginResponse.Allow;

        logger.LogWarning("NewUserConn rejected — banned IP {Ip} (proxy={Proxy}, type={Type})",
            ip, connection!.ProxyName, connection.ProxyType);
        return PluginResponse.Deny($"IP {ip} is banned");
    }

    /// <summary>Returns the canonical IP from "IP", "IP:port" or "[IPv6]:port", or null.</summary>
    private static string? ParseIp(string? address)
    {
        if (string.IsNullOrWhiteSpace(address))
            return null;
        if (IpAddressUtilities.Normalize(address) is { } literal)
            return literal;
        return IPEndPoint.TryParse(address, out var endpoint)
            ? IpAddressUtilities.Normalize(endpoint.Address.ToString())
            : null;
    }
}
