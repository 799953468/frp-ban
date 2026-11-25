using Microsoft.Extensions.Options;

namespace FrpBan.Client.Configuration;

/// <summary>Runs <see cref="ClientSettings.Validate()"/> when the host starts.</summary>
public sealed class ClientSettingsValidator : IValidateOptions<ClientSettings>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, ClientSettings options)
    {
        var errors = options.Validate().Select(result => result.ErrorMessage ?? "Invalid client settings.").ToArray();
        return errors.Length > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
