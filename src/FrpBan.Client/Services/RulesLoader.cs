using FrpBan.Client.Configuration;
using Microsoft.Extensions.Logging;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace FrpBan.Client.Services;

/// <summary>
/// Loads ban rules from YAML configuration files.
/// Supports both single file and conf.d style directory.
/// </summary>
public sealed class RulesLoader
{
    private readonly ILogger<RulesLoader> _logger;

    public RulesLoader(ILogger<RulesLoader> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Loads rules from a YAML file or directory (conf.d style).
    /// If path is a directory, loads all .yaml and .yml files in it.
    /// </summary>
    public List<BanRule> LoadRules(string? rulesPath)
    {
        var rules = new List<BanRule>();

        if (string.IsNullOrWhiteSpace(rulesPath))
        {
            _logger.LogWarning("Rules path not configured, no rules will be loaded");
            return rules;
        }

        if (Directory.Exists(rulesPath))
        {
            // Load all YAML files from directory
            _logger.LogInformation("Loading rules from directory: {Path}", rulesPath);
            rules = LoadRulesFromDirectory(rulesPath);
        }
        else if (File.Exists(rulesPath))
        {
            // Load single file
            _logger.LogInformation("Loading rules from file: {Path}", rulesPath);
            var fileRules = LoadRulesFromFile(rulesPath);
            rules.AddRange(fileRules);
        }
        else
        {
            _logger.LogError("Rules path not found (not a file or directory): {Path}", rulesPath);
            return rules;
        }

        _logger.LogInformation("Loaded {Count} total rule(s)", rules.Count);
        foreach (var rule in rules)
        {
            _logger.LogInformation("  Rule: {Name} (enabled={Enabled})", rule.Name, rule.Enabled);
        }

        return rules;
    }

    private List<BanRule> LoadRulesFromDirectory(string directoryPath)
    {
        var rules = new List<BanRule>();

        try
        {
            var files = Directory.GetFiles(directoryPath, "*.yaml")
                .Concat(Directory.GetFiles(directoryPath, "*.yml"))
                .OrderBy(f => f)
                .ToList();

            _logger.LogInformation("Found {Count} YAML file(s) in {Path}", files.Count, directoryPath);

            foreach (var file in files)
            {
                _logger.LogDebug("Loading rules from {File}", file);
                var fileRules = LoadRulesFromFile(file);
                rules.AddRange(fileRules);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load rules from directory {Path}", directoryPath);
        }

        return rules;
    }

    private List<BanRule> LoadRulesFromFile(string filePath)
    {
        var rules = new List<BanRule>();

        try
        {
            var yaml = File.ReadAllText(filePath);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .Build();

            var config = deserializer.Deserialize<RulesConfiguration>(yaml);
            if (config?.Rules != null)
            {
                rules = config.Rules;
                _logger.LogInformation("  Loaded {Count} rule(s) from {File}", rules.Count, Path.GetFileName(filePath));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load rules from file {Path}", filePath);
        }

        return rules;
    }
}
