using System.Net;
using FrpBan.Configuration;
using Microsoft.Extensions.Options;

namespace FrpBan.Security;

/// <summary>Precompiles the trusted frps callback address list once at startup.</summary>
public sealed class PluginAddressFilter
{
    private readonly IPNetwork[] _networks;

    /// <summary>Parses exact addresses and CIDRs, rejecting invalid configuration.</summary>
    public PluginAddressFilter(IOptions<PluginSettings> settings)
    {
        _networks = settings.Value.AllowedPluginAddresses.Select(value =>
        {
            if (IPAddress.TryParse(value, out var address))
            {
                if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
                return new IPNetwork(address, address.GetAddressBytes().Length * 8);
            }
            return IPNetwork.Parse(value);
        }).ToArray();
    }

    /// <summary>Checks a socket peer against the configured list; an empty list explicitly allows all.</summary>
    /// <param name="address">The actual socket peer, without forwarded-header substitution.</param>
    /// <returns>True when this peer may invoke the plugin.</returns>
    public bool IsAllowed(IPAddress? address)
    {
        if (_networks.Length == 0) return true;
        if (address is null) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return _networks.Any(network => network.Contains(address));
    }
}
