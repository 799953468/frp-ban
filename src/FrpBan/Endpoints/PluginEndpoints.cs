using FrpBan.Handlers;
using FrpBan.Models;
using FrpBan.Security;
using Microsoft.AspNetCore.Mvc;

namespace FrpBan.Endpoints;

/// <summary>Maps the frps callback and its pre-body address authorization.</summary>
public static class PluginEndpoints
{
    /// <summary>Registers the callback middleware and route using the trusted socket address.</summary>
    /// <param name="app">The server application.</param>
    public static void MapPluginEndpoints(this WebApplication app)
    {
        var filter = app.Services.GetRequiredService<PluginAddressFilter>();
        app.Use(async (context, next) =>
        {
            // Include route aliases such as /handler/ before JSON model binding.
            if (context.Request.Path.StartsWithSegments("/handler", StringComparison.OrdinalIgnoreCase) &&
                !filter.IsAllowed(context.Connection.RemoteIpAddress))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(PluginResponse.Deny("not allowed"), context.RequestAborted);
                return;
            }
            await next(context);
        });
        app.MapPost("/handler", async ([FromBody] PluginRequest request, HttpContext context, PluginRequestHandler handler) =>
            Results.Json(await handler.HandleAsync(request, context)));
    }
}
