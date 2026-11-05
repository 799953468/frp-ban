using System.Net;
using FrpBan.Configuration;
using FrpBan.Handlers;
using FrpBan.Middleware;
using FrpBan.Models;
using FrpBan.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------
builder.Services.AddOptions<PluginSettings>()
    .Bind(builder.Configuration.GetSection("PluginSettings"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// -------------------------------------------------------------------------
// Services
// -------------------------------------------------------------------------
builder.Services.AddSingleton<BanService>();
builder.Services.AddSingleton<IBanService>(sp => sp.GetRequiredService<BanService>());
builder.Services.AddSingleton<IAccessLogService, AccessLogService>();
builder.Services.AddSingleton<PluginRequestHandler>();

var app = builder.Build();

// Load persisted bans before accepting traffic.
app.Services.GetRequiredService<BanService>().Load();

// -------------------------------------------------------------------------
// Middleware
// -------------------------------------------------------------------------
app.UseMiddleware<TokenAuthMiddleware>();

// -------------------------------------------------------------------------
// Routes — frps plugin endpoint
// -------------------------------------------------------------------------

/// <summary>
/// POST /handler  — called by frps for every plugin operation.
/// Restricted to addresses listed in AllowedPluginAddresses.
/// </summary>
app.MapPost("/handler", async (
    [FromBody] PluginRequest request,
    HttpContext ctx,
    PluginRequestHandler handler,
    IOptions<PluginSettings> opts) =>
{
    var allowed = opts.Value.AllowedPluginAddresses;
    if (allowed.Count > 0)
    {
        var remote = ctx.Connection.RemoteIpAddress;
        if (remote is null || !allowed.Any(a =>
            IPAddress.TryParse(a, out var parsed) && parsed.Equals(remote)))
        {
            return Results.Json(PluginResponse.Deny("not allowed"), statusCode: 403);
        }
    }

    var response = await handler.HandleAsync(request, ctx);
    return Results.Json(response);
});

// -------------------------------------------------------------------------
// Routes — ban management API (protected by TokenAuthMiddleware)
// -------------------------------------------------------------------------

var api = app.MapGroup("/api");

/// <summary>GET /api/bans — list all active bans.</summary>
api.MapGet("/bans", (IBanService bans) =>
    Results.Ok(bans.GetActiveBans()));

/// <summary>
/// POST /api/bans — add an IP to the ban list.
/// Body: { "ip": "1.2.3.4", "reason": "...", "durationSeconds": 3600 }
/// </summary>
api.MapPost("/bans", async (
    [FromBody] BanRequest req,
    IBanService bans,
    IAccessLogService accessLog,
    HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(req.Ip) || !IPAddress.TryParse(req.Ip, out _))
        return Results.BadRequest("Invalid IP address.");

    var reason = req.Reason ?? "api request";
    await bans.BanAsync(req.Ip, reason, req.DurationSeconds);

    var caller = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    accessLog.LogBanAction(caller, "BAN", req.Ip);

    return Results.Ok(new { banned = req.Ip, reason, durationSeconds = req.DurationSeconds });
});

/// <summary>DELETE /api/bans/{ip} — remove a ban.</summary>
api.MapDelete("/bans/{ip}", async (
    string ip,
    IBanService bans,
    IAccessLogService accessLog,
    HttpContext ctx) =>
{
    await bans.UnbanAsync(ip);

    var caller = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    accessLog.LogBanAction(caller, "UNBAN", ip);

    return Results.Ok(new { unbanned = ip });
});

app.Run();
