using System.Net;
using System.Text.Json;
using FrpBan.Models;
using FrpBan.Services;

namespace FrpBan.Handlers;

/// <summary>
/// Processes frps plugin HTTP callbacks and returns allow/deny decisions
/// based on the current IP ban list.
/// </summary>
public sealed class PluginRequestHandler(
    IBanService banService,
    ILogger<PluginRequestHandler> logger)
{
    /// <summary>
    /// Handles an inbound plugin request from frps and returns a <see cref="PluginResponse"/>.
    /// </summary>
    public Task<PluginResponse> HandleAsync(PluginRequest request, HttpContext ctx)
    {
        logger.LogDebug("Plugin op={Op} reqid={ReqId}", request.Op,
            ctx.Request.Headers["X-Frp-Reqid"]);

        return request.Op switch
        {
            "Login"       => HandleLoginAsync(request),
            "NewUserConn" => HandleNewUserConnAsync(request),
            // All other ops (NewProxy, Ping, NewWorkConn, CloseProxy) are allowed.
            _ => Task.FromResult(PluginResponse.Allow),
        };
    }

    // -------------------------------------------------------------------------
    // Operation handlers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Checks whether the frpc client's IP is banned before the client is
    /// allowed to authenticate and register proxies.
    /// </summary>
    private Task<PluginResponse> HandleLoginAsync(PluginRequest request)
    {
        var content = request.Content.Deserialize<LoginContent>();
        if (content is null)
            return Task.FromResult(PluginResponse.Deny("invalid login payload"));

        var ip = ParseIp(content.ClientAddress);
        if (ip is not null && banService.IsBanned(ip))
        {
            logger.LogWarning("Login rejected — banned IP {Ip} (run_id={RunId})",
                ip, content.RunId);
            return Task.FromResult(PluginResponse.Deny($"IP {ip} is banned"));
        }

        return Task.FromResult(PluginResponse.Allow);
    }

    /// <summary>
    /// Checks whether the end-user's IP (the person connecting through the
    /// frp tunnel) is banned before allowing the connection to be forwarded.
    /// </summary>
    private Task<PluginResponse> HandleNewUserConnAsync(PluginRequest request)
    {
        var content = request.Content.Deserialize<NewUserConnContent>();
        if (content is null)
            return Task.FromResult(PluginResponse.Deny("invalid NewUserConn payload"));

        var ip = ParseIp(content.RemoteAddr);
        if (ip is not null && banService.IsBanned(ip))
        {
            logger.LogWarning(
                "NewUserConn rejected — banned IP {Ip} (proxy={Proxy}, type={Type})",
                ip, content.ProxyName, content.ProxyType);
            return Task.FromResult(PluginResponse.Deny($"IP {ip} is banned"));
        }

        return Task.FromResult(PluginResponse.Allow);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Parses the IP from an "IP:port" string, or returns null on failure.
    /// </summary>
    private static string? ParseIp(string address)
    {
        if (string.IsNullOrWhiteSpace(address)) return null;

        // IPEndPoint.TryParse handles both "1.2.3.4:80" and "[::1]:80".
        if (IPEndPoint.TryParse(address, out var endpoint))
            return endpoint.Address.ToString();

        // Fallback: address without a port.
        if (IPAddress.TryParse(address, out var addr))
            return addr.ToString();

        return null;
    }
}
