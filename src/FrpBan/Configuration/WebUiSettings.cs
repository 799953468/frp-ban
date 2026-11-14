using System.ComponentModel.DataAnnotations;
using FrpBan.Security;

namespace FrpBan.Configuration;

/// <summary>Opt-in browser management settings, independent of TLS client credentials.</summary>
public sealed class WebUiSettings
{
    /// <summary>Enables the management page and API at /admin.</summary>
    public bool Enabled { get; set; }

    /// <summary>A separate management secret, supplied through configuration or an environment variable.</summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>Trusted socket IPs/CIDRs. Empty permits any address with a valid management token.</summary>
    public List<string> AllowedAddresses { get; set; } = ["127.0.0.1", "::1"];

    /// <summary>Validates enabled management settings without reflection for Native AOT.</summary>
    /// <param name="clientToken">The TLS client token, which must not grant management access.</param>
    /// <returns>Configuration errors that prevent the server from starting.</returns>
    public IEnumerable<ValidationResult> Validate(string clientToken)
    {
        if (!Enabled)
        {
            yield break;
        }

        if (string.IsNullOrWhiteSpace(Token) || Token.Length is < 32 or > 256 ||
            Token.StartsWith("CHANGE_ME", StringComparison.OrdinalIgnoreCase) ||
            Token.Any(character => character is < '!' or > '~'))
        {
            yield return new ValidationResult("WebUi.Token must be a non-placeholder secret of 32–256 printable ASCII characters without spaces.");
        }

        if (string.Equals(Token, clientToken, StringComparison.Ordinal))
        {
            yield return new ValidationResult("WebUi.Token must differ from the TLS client Token.");
        }

        if (AllowedAddresses is null)
        {
            yield return new ValidationResult("WebUi.AllowedAddresses must be an array of IP addresses or CIDR networks.");
            yield break;
        }

        foreach (var address in AllowedAddresses)
        {
            if (!IpExemptionList.TryParseNetwork(address, out _))
            {
                yield return new ValidationResult($"Invalid WebUi.AllowedAddresses entry: '{address}'.");
            }
        }
    }
}