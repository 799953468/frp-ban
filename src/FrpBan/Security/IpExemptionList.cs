using System.Net;
using System.Net.Sockets;

namespace FrpBan.Security;

/// <summary>Compiles an immutable set of exact IP addresses and CIDRs exempt from bans.</summary>
internal sealed class IpExemptionList
{
    private readonly IPNetwork[] _networks;

    public IpExemptionList(IEnumerable<string> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var networks = new List<IPNetwork>();
        foreach (var entry in entries)
        {
            if (!TryParseNetwork(entry, out var network))
            {
                throw new ArgumentException($"Invalid ExemptAddresses entry: '{entry}'. Expected an IP address or CIDR network.",
                    nameof(entries));
            }

            networks.Add(network);
        }

        _networks = networks.ToArray();
    }

    public bool Contains(string? value)
    {
        if (_networks.Length == 0 || !IPAddress.TryParse(value, out var address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        foreach (var network in _networks)
        {
            if (network.Contains(address))
            {
                return true;
            }
        }

        return false;
    }

    internal static bool TryParseNetwork(string? value, out IPNetwork network)
    {
        if (IPAddress.TryParse(value, out var address))
        {
            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            var prefixLength = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            network = new IPNetwork(address, prefixLength);
            return true;
        }

        if (!IPNetwork.TryParse(value, out network))
        {
            return false;
        }

        // Reject host bits even on runtimes that silently normalize CIDR input.
        var separator = value!.IndexOf('/');
        if (separator < 0 || !IPAddress.TryParse(value.AsSpan(0, separator), out var baseAddress) ||
            !baseAddress.Equals(network.BaseAddress))
        {
            return false;
        }

        // Keep IPv4-mapped CIDRs consistent with canonical IPv4 ban keys.
        if (network.BaseAddress.IsIPv4MappedToIPv6)
        {
            if (network.PrefixLength < 96)
            {
                return false;
            }

            network = new IPNetwork(network.BaseAddress.MapToIPv4(), network.PrefixLength - 96);
        }

        return true;
    }
}