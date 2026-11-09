using System.Net;

namespace FrpBan.Protocol;

/// <summary>Provides canonical IP keys shared by ban storage, callbacks, and rule matching.</summary>
public static class IpAddressUtilities
{
    /// <summary>Normalizes an IP address, including IPv4-mapped IPv6, or returns null for invalid input.</summary>
    /// <param name="value">An IP literal without a port.</param>
    /// <returns>The canonical IP literal, or null when parsing fails.</returns>
    public static string? Normalize(string? value) => IPAddress.TryParse(value, out var address)
        ? (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString()
        : null;
}
