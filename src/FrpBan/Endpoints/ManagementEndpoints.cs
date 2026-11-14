using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FrpBan.Configuration;
using FrpBan.Models;
using FrpBan.Protocol;
using FrpBan.Security;
using FrpBan.Services;
using Microsoft.Extensions.Options;

namespace FrpBan.Endpoints;

/// <summary>Hosts the embedded management page and authenticated ban-management API.</summary>
public static class ManagementEndpoints
{
    /// <summary>Registers opt-in management routes and authorizes requests before reading their bodies.</summary>
    /// <param name="app">The server application.</param>
    public static void MapManagementEndpoints(this WebApplication app)
    {
        var settings = app.Services.GetRequiredService<IOptions<PluginSettings>>().Value;
        if (!settings.WebUi.Enabled)
        {
            return;
        }

        var errors = settings.WebUi.Validate(settings.Token).Select(result => result.ErrorMessage!).ToArray();
        if (errors.Length != 0)
        {
            throw new OptionsValidationException(nameof(PluginSettings), typeof(PluginSettings), errors);
        }

        var allowedAddresses = new IpExemptionList(settings.WebUi.AllowedAddresses);
        var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(settings.WebUi.Token));
        var limiter = new IpRateLimiter(120);

        app.Use(async (context, next) =>
        {
            if (!context.Request.Path.StartsWithSegments("/admin", StringComparison.OrdinalIgnoreCase))
            {
                await next(context);
                return;
            }

            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers.ContentSecurityPolicy =
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
                "img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

            var address = context.Connection.RemoteIpAddress;
            if (address is null || (settings.WebUi.AllowedAddresses.Count != 0 && !allowedAddresses.Contains(address.ToString())))
            {
                await Error("Management access is not allowed from this address.", StatusCodes.Status403Forbidden).ExecuteAsync(context);
                return;
            }

            if (context.Request.Path.StartsWithSegments("/admin/api", StringComparison.OrdinalIgnoreCase))
            {
                var rateLimitKey = address.IsIPv4MappedToIPv6 ? address.MapToIPv4().ToString() : address.ToString();
                if (!limiter.TryAcquire(rateLimitKey))
                {
                    context.Response.Headers.RetryAfter = "60";
                    await Error("Too many management requests. Try again in one minute.", StatusCodes.Status429TooManyRequests).ExecuteAsync(context);
                    return;
                }

                if (!IsAuthorized(context, tokenHash))
                {
                    context.Response.Headers.WWWAuthenticate = "Bearer";
                    await Error("Enter a valid management token.", StatusCodes.Status401Unauthorized).ExecuteAsync(context);
                    return;
                }
            }

            await next(context);
        });

        var html = ReadAsset("index.html");
        var css = ReadAsset("app.css");
        var javascript = ReadAsset("app.js");
        app.MapGet("/admin", (HttpContext context) =>
        {
            if (!context.Request.Path.Value!.EndsWith('/'))
            {
                return Results.Redirect(context.Request.PathBase + "/admin/");
            }

            return Results.Text(html, "text/html; charset=utf-8");
        });
        app.MapGet("/admin/app.css", () => { return Results.Text(css, "text/css; charset=utf-8"); });
        app.MapGet("/admin/app.js", () => { return Results.Text(javascript, "text/javascript; charset=utf-8"); });
        app.MapGet("/admin/api/bans", ListBans);
        app.MapPost("/admin/api/bans", CreateBanAsync);
        app.MapDelete("/admin/api/bans/{ip}", RemoveBanAsync);
    }

    private static bool IsAuthorized(HttpContext context, byte[] expectedHash)
    {
        var headers = context.Request.Headers.Authorization;
        if (headers.Count != 1)
        {
            return false;
        }

        var header = headers[0];
        if (header is null || header.Length is < 39 or > 263 || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var actualHash = SHA256.HashData(Encoding.UTF8.GetBytes(header.AsSpan(7).ToString()));
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }

    private static IResult ListBans(HttpContext context, IBanService bans, IOptions<PluginSettings> options)
    {
        var query = context.Request.Query;
        var search = query["search"].ToString().Trim();
        var kind = query["kind"].ToString();
        if (search.Length > 256 || kind is not ("" or "all" or "temporary" or "permanent") ||
            !TryReadPositiveInt(query["page"].ToString(), 1, int.MaxValue, out var page) ||
            !TryReadPositiveInt(query["pageSize"].ToString(), 25, 100, out var pageSize))
        {
            return Error("Invalid search, kind, page, or pageSize (maximum 100).", StatusCodes.Status400BadRequest);
        }

        var active = bans.GetActiveBans();
        var filtered = active.Where(entry =>
                (kind != "permanent" || entry.ExpiresAt is null) &&
                (kind != "temporary" || entry.ExpiresAt is not null) &&
                (entry.Ip.Contains(search, StringComparison.OrdinalIgnoreCase) || entry.Reason.Contains(search, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(entry => entry.BannedAt)
            .ThenBy(entry => entry.Ip, StringComparer.Ordinal)
            .ToArray();
        page = Math.Min(page, Math.Max(1, (int)Math.Ceiling(filtered.Length / (double)pageSize)));
        var items = filtered.Skip((page - 1) * pageSize).Take(pageSize).ToArray();
        var response = new BanListResponse(items, filtered.Length, page, pageSize, active.Count,
            active.Count(entry => entry.ExpiresAt is null), options.Value.DefaultBanDurationSeconds);
        return Results.Json(response, ManagementJsonContext.Default.BanListResponse);
    }

    private static async Task<IResult> CreateBanAsync(HttpContext context, IBanService bans)
    {
        if (!context.Request.HasJsonContentType())
        {
            return Error("Send an application/json request body.", StatusCodes.Status415UnsupportedMediaType);
        }

        CreateBanRequest? request;
        try
        {
            request = await context.Request.ReadFromJsonAsync(ManagementJsonContext.Default.CreateBanRequest, context.RequestAborted);
        }
        catch (JsonException)
        {
            return Error("The ban request must contain valid JSON.", StatusCodes.Status400BadRequest);
        }

        var ip = IpAddressUtilities.Normalize(request?.Ip);
        if (ip is null || string.IsNullOrWhiteSpace(request?.Reason) || request.Reason.Length > 1024 || request.DurationSeconds < 0)
        {
            return Error("Provide a valid IP address, a reason of 1–1024 characters, and a non-negative duration in seconds.", StatusCodes.Status400BadRequest);
        }

        if (bans.IsExempt(ip))
        {
            return Error("This address is exempt from bans. Check ExemptAddresses in the server configuration.", StatusCodes.Status409Conflict);
        }

        try
        {
            await bans.BanAsync(ip, request.Reason.Trim(), request.DurationSeconds);
        }
        catch (InvalidOperationException)
        {
            return Error("Ban capacity reached. Remove an existing ban before adding another.", StatusCodes.Status409Conflict);
        }
        catch (IOException)
        {
            return Error("Ban changes could not be saved. Check server storage and retry.", StatusCodes.Status503ServiceUnavailable);
        }

        return Results.NoContent();
    }

    private static async Task<IResult> RemoveBanAsync(string ip, IBanService bans)
    {
        var normalized = IpAddressUtilities.Normalize(ip);
        if (normalized is null)
        {
            return Error("Provide a valid IP address.", StatusCodes.Status400BadRequest);
        }

        try
        {
            await bans.UnbanAsync(normalized);
        }
        catch (IOException)
        {
            return Error("Ban changes could not be saved. Check server storage and retry.", StatusCodes.Status503ServiceUnavailable);
        }

        return Results.NoContent();
    }

    private static bool TryReadPositiveInt(string value, int fallback, int maximum, out int result)
    {
        if (value.Length == 0)
        {
            result = fallback;
            return true;
        }

        return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out result) && result >= 1 && result <= maximum;
    }

    private static IResult Error(string message, int statusCode)
    {
        return Results.Json(new ManagementError(message), ManagementJsonContext.Default.ManagementError, statusCode: statusCode);
    }

    private static string ReadAsset(string name)
    {
        using (var stream = typeof(ManagementEndpoints).Assembly.GetManifestResourceStream("FrpBan.WebUi." + name)
                            ?? throw new InvalidOperationException("Missing embedded management asset: " + name))
        using (var reader = new StreamReader(stream))
        {
            return reader.ReadToEnd();
        }
    }
}