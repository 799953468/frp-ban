using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Sockets;

namespace FrpBan.Security;

/// <summary>
/// An immutable list of exact IP addresses and CIDR networks, used for ban exemptions and
/// for the plugin and management allow lists. IPv4-mapped IPv6 input is treated as IPv4.
/// </summary>
internal sealed class IpNetworkList
{
    private readonly IPNetwork[] _networks;

    /// <summary>Compiles the entries, rejecting anything <see cref="TryParseNetwork"/> rejects.</summary>
    /// <param name="entries">IP addresses or CIDR networks.</param>
    /// <param name="settingName">Configuration key named in error messages.</param>
    public IpNetworkList(IEnumerable<string> entries, string settingName = "address list")
    {
        ArgumentNullException.ThrowIfNull(entries);
        var networks = new List<IPNetwork>();
        foreach (var entry in entries)
        {
            if (!TryParseNetwork(entry, out var network))
            {
                throw new ArgumentException(InvalidEntryMessage(settingName, entry), nameof(entries));
            }

            networks.Add(network);
        }

        _networks = networks.ToArray();
    }

    /// <summary>True when the list has no entries. Callers decide whether that means "none" or "all".</summary>
    public bool IsEmpty => _networks.Length == 0;

    /// <summary>Returns whether a textual IP address falls in any entry; invalid input never matches.</summary>
    public bool Contains(string? value) => IPAddress.TryParse(value, out var address) && Contains(address);

    /// <summary>Returns whether an address falls in any entry; null never matches.</summary>
    public bool Contains(IPAddress? address)
    {
        if (address is null || _networks.Length == 0)
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

    /// <summary>Validates a configured list without constructing it, for startup option validation.</summary>
    /// <param name="entries">The configured entries, possibly null when bound from bad configuration.</param>
    /// <param name="settingName">Configuration key named in error messages.</param>
    public static IEnumerable<ValidationResult> Validate(List<string>? entries, string settingName)
    {
        if (entries is null)
        {
            yield return new ValidationResult($"{settingName} must be an array of IP addresses or CIDR networks.", [settingName]);
            yield break;
        }

        foreach (var entry in entries)
        {
            if (!TryParseNetwork(entry, out _))
            {
                yield return new ValidationResult(InvalidEntryMessage(settingName, entry), [settingName]);
            }
        }
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

    private static string InvalidEntryMessage(string settingName, string? entry) =>
        $"Invalid {settingName} entry: '{entry}'. Expected an IP address or CIDR network with no host bits set.";
}
