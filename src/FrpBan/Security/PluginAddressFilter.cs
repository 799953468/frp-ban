using System.Net;
using FrpBan.Configuration;
using Microsoft.Extensions.Options;

namespace FrpBan.Security;

/// <summary>Precompiles the trusted frps callback address list once at startup.</summary>
public sealed class PluginAddressFilter
{
    private readonly IpNetworkList _networks;

    /// <summary>Compiles AllowedPluginAddresses, rejecting invalid entries.</summary>
    public PluginAddressFilter(IOptions<PluginSettings> settings)
    {
        _networks = new IpNetworkList(settings.Value.AllowedPluginAddresses, nameof(PluginSettings.AllowedPluginAddresses));
    }

    /// <summary>Checks a socket peer against the configured list; an empty list explicitly allows all.</summary>
    /// <param name="address">The actual socket peer, without forwarded-header substitution.</param>
    /// <returns>True when this peer may invoke the plugin.</returns>
    public bool IsAllowed(IPAddress? address) => _networks.IsEmpty || _networks.Contains(address);
}
