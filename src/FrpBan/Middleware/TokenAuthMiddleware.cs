using FrpBan.Configuration;
using FrpBan.Services;
using Microsoft.Extensions.Options;

namespace FrpBan.Middleware;

/// <summary>
/// Enforces Bearer-token authentication on all routes under /api/.
/// Requests with an invalid or missing token receive 401 and are
/// logged to the fail2ban access log.
/// </summary>
public sealed class TokenAuthMiddleware(
    RequestDelegate next,
    IOptions<PluginSettings> settings,
    IAccessLogService accessLog)
{
    private readonly string _token = settings.Value.Token;

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (!ctx.Request.Path.StartsWithSegments("/api"))
        {
            await next(ctx);
            return;
        }

        var remoteIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var providedToken = ExtractToken(ctx.Request);

        if (string.IsNullOrEmpty(providedToken) || !ConstantTimeEquals(providedToken, _token))
        {
            accessLog.LogUnauthorized(remoteIp, ctx.Request.Path, ctx.Request.Method);
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsync("Unauthorized");
            return;
        }

        await next(ctx);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Extracts the token from the Authorization header ("Bearer &lt;token&gt;").
    /// Query parameter fallback is intentionally not supported to prevent token leakage in logs.
    /// </summary>
    private static string? ExtractToken(HttpRequest request)
    {
        var authHeader = request.Headers.Authorization.ToString();
        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return authHeader["Bearer ".Length..].Trim();

        return null;
    }

    /// <summary>
    /// Constant-time string comparison to prevent timing attacks on token validation.
    /// </summary>
    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length)
            return false;

        var diff = 0;
        for (var i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];

        return diff == 0;
    }
}
