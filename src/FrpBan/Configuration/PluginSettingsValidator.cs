using Microsoft.Extensions.Options;

namespace FrpBan.Configuration;

/// <summary>Runs <see cref="PluginSettings.Validate()"/> when options are first resolved and at startup.</summary>
public sealed class PluginSettingsValidator : IValidateOptions<PluginSettings>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, PluginSettings options)
    {
        var errors = options.Validate().Select(result => result.ErrorMessage ?? "Invalid server settings.").ToArray();
        if (errors.Length > 0)
        {
            return ValidateOptionsResult.Fail(errors);
        }

        return ValidateOptionsResult.Success;
    }
}