using FrpBan.Client.Configuration;
using FrpBan.Client.Matching;
using Microsoft.Extensions.Logging;

namespace FrpBan.Client.Services;

/// <summary>
/// Loads and compiles ban rules from a YAML file or a conf.d style directory.
/// Unreadable files and invalid or duplicate rules are logged and skipped; the remaining rules still load.
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
    /// If path is a directory, loads all .yaml and .yml files in it, in ordinal file-name order.
    /// </summary>
    public List<CompiledRule> LoadRules(string? rulesPath)
    {
        var rules = new List<BanRule>();

        if (string.IsNullOrWhiteSpace(rulesPath))
        {
            _logger.LogWarning("Rules path not configured, no rules will be loaded");
            return [];
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
            return [];
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        var compiled = new List<CompiledRule>();
        foreach (var rule in rules)
        {
            if (rule is null)
            {
                _logger.LogError("Ignoring null rule");
                continue;
            }

            try
            {
                var compiledRule = CompiledRule.Compile(rule);
                if (!names.Add(rule.Name))
                {
                    _logger.LogError("Ignoring rule {Name}: Duplicate rule name", rule.Name);
                    continue;
                }

                compiled.Add(compiledRule);
            }
            catch (InvalidDataException ex)
            {
                _logger.LogError("Ignoring rule {Name}: {Error}", rule.Name, ex.Message);
            }
        }

        _logger.LogInformation("Loaded {Count} total rule(s)", compiled.Count);
        foreach (var rule in compiled)
        {
            _logger.LogInformation("  Rule: {Name} (enabled={Enabled})", rule.Name, rule.Enabled);
        }

        return compiled;
    }

    private List<BanRule> LoadRulesFromDirectory(string directoryPath)
    {
        var rules = new List<BanRule>();

        try
        {
            var files = Directory.GetFiles(directoryPath, "*.yaml")
                .Concat(Directory.GetFiles(directoryPath, "*.yml"))
                .OrderBy(f => f, StringComparer.Ordinal)
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
            var config = RulesYamlParser.Parse(yaml);
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