using System.Globalization;
using FrpBan.Client.Configuration;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace FrpBan.Client.Services;

/// <summary>Maps the YAML document to rules without runtime reflection or dynamic code.</summary>
internal static class RulesYamlParser
{
    public static RulesConfiguration? Parse(string yaml)
    {
        var stream = new YamlStream();
        using (var reader = new StringReader(yaml))
        {
            stream.Load(reader);
        }

        if (stream.Documents.Count == 0 || IsNull(stream.Documents[0].RootNode))
        {
            return null;
        }

        if (stream.Documents.Count != 1)
        {
            throw new InvalidDataException("A rule file must contain a single YAML document.");
        }

        return ReadRulesConfiguration(stream.Documents[0].RootNode);
    }

    private static RulesConfiguration ReadRulesConfiguration(YamlNode node)
    {
        var values = ReadMapping(node, "rules");
        var defaults = new RulesConfiguration();
        return new RulesConfiguration
        {
            Rules = values.TryGetValue("rules", out var valueRules)
                ? ReadList(valueRules, ReadBanRule)
                : defaults.Rules,
        };
    }

    private static BanRule ReadBanRule(YamlNode node)
    {
        var values = ReadMapping(node, "name", "enabled", "logSource", "matching", "action", "maxTrackedIps");
        var defaults = new BanRule();
        return new BanRule
        {
            Name = values.TryGetValue("name", out var valueName)
                ? ReadString(valueName)!
                : defaults.Name,
            Enabled = values.TryGetValue("enabled", out var valueEnabled)
                ? ReadBoolean(valueEnabled)
                : defaults.Enabled,
            LogSource = values.TryGetValue("logSource", out var valueLogSource)
                ? IsNull(valueLogSource) ? null! : ReadLogSource(valueLogSource)
                : defaults.LogSource,
            Matching = values.TryGetValue("matching", out var valueMatching)
                ? ReadList(valueMatching, ReadMatchExpression)
                : defaults.Matching,
            Action = values.TryGetValue("action", out var valueAction)
                ? IsNull(valueAction) ? null! : ReadBanAction(valueAction)
                : defaults.Action,
            MaxTrackedIps = values.TryGetValue("maxTrackedIps", out var valueMaxTrackedIps)
                ? ReadInteger(valueMaxTrackedIps)
                : defaults.MaxTrackedIps,
        };
    }

    private static LogSource ReadLogSource(YamlNode node)
    {
        var values = ReadMapping(node, "type", "path", "service");
        var defaults = new LogSource();
        return new LogSource
        {
            Type = values.TryGetValue("type", out var valueType)
                ? ReadString(valueType)!
                : defaults.Type,
            Path = values.TryGetValue("path", out var valuePath)
                ? ReadString(valuePath)!
                : defaults.Path,
            Service = values.TryGetValue("service", out var valueService)
                ? ReadString(valueService)!
                : defaults.Service,
        };
    }

    private static MatchExpression ReadMatchExpression(YamlNode node)
    {
        var values = ReadMapping(node, "type", "pattern", "jsonPath", "jsonValue", "ipJsonPath");
        var defaults = new MatchExpression();
        return new MatchExpression
        {
            Type = values.TryGetValue("type", out var valueType)
                ? ReadString(valueType)!
                : defaults.Type,
            Pattern = values.TryGetValue("pattern", out var valuePattern)
                ? ReadString(valuePattern)!
                : defaults.Pattern,
            JsonPath = values.TryGetValue("jsonPath", out var valueJsonPath)
                ? ReadString(valueJsonPath)!
                : defaults.JsonPath,
            JsonValue = values.TryGetValue("jsonValue", out var valueJsonValue)
                ? ReadString(valueJsonValue)!
                : defaults.JsonValue,
            IpJsonPath = values.TryGetValue("ipJsonPath", out var valueIpJsonPath)
                ? ReadString(valueIpJsonPath)!
                : defaults.IpJsonPath,
        };
    }

    private static BanAction ReadBanAction(YamlNode node)
    {
        var values = ReadMapping(node, "type", "windowSeconds", "maxMatches", "banDurationSeconds", "reason");
        var defaults = new BanAction();
        return new BanAction
        {
            Type = values.TryGetValue("type", out var valueType)
                ? ReadString(valueType)!
                : defaults.Type,
            WindowSeconds = values.TryGetValue("windowSeconds", out var valueWindowSeconds)
                ? ReadInteger(valueWindowSeconds)
                : defaults.WindowSeconds,
            MaxMatches = values.TryGetValue("maxMatches", out var valueMaxMatches)
                ? ReadInteger(valueMaxMatches)
                : defaults.MaxMatches,
            BanDurationSeconds = values.TryGetValue("banDurationSeconds", out var valueBanDurationSeconds)
                ? ReadInteger(valueBanDurationSeconds)
                : defaults.BanDurationSeconds,
            Reason = values.TryGetValue("reason", out var valueReason)
                ? ReadString(valueReason)!
                : defaults.Reason,
        };
    }

    private static Dictionary<string, YamlNode> ReadMapping(YamlNode node, params string[] allowedKeys)
    {
        if (node is not YamlMappingNode mapping)
        {
            throw new InvalidDataException("Expected a YAML mapping.");
        }

        var values = new Dictionary<string, YamlNode>(StringComparer.Ordinal);
        foreach (var (key, value) in mapping.Children)
        {
            var name = ReadString(key);
            if (name is null || !allowedKeys.Contains(name, StringComparer.Ordinal))
            {
                throw new InvalidDataException($"Unknown rule property: {name}");
            }

            values.Add(name, value);
        }

        return values;
    }

    private static List<T> ReadList<T>(YamlNode node, Func<YamlNode, T> readItem)
    {
        if (IsNull(node))
        {
            return null!;
        }

        if (node is not YamlSequenceNode sequence)
        {
            throw new InvalidDataException("Expected a YAML sequence.");
        }

        var items = new List<T>();
        foreach (var child in sequence.Children)
        {
            items.Add(IsNull(child) ? default! : readItem(child));
        }

        return items;
    }

    private static string? ReadString(YamlNode node)
    {
        if (node is not YamlScalarNode scalar)
        {
            throw new InvalidDataException("Expected a YAML scalar.");
        }

        return IsNull(node) ? null : scalar.Value;
    }

    private static bool ReadBoolean(YamlNode node)
    {
        // Preserve the YAML 1.1 scalar forms accepted by the previous deserializer.
        return ReadString(node)?.ToLowerInvariant() switch
        {
            "true" or "y" or "yes" or "on" => true,
            "false" or "n" or "no" or "off" or null => false,
            _ => throw new FormatException("Expected a YAML Boolean."),
        };
    }

    private static int ReadInteger(YamlNode node)
    {
        var text = ReadString(node);
        if (text is null)
        {
            return 0;
        }

        var negative = text.StartsWith('-');
        if (negative || text.StartsWith('+'))
        {
            text = text[1..];
        }

        text = text.Replace("_", "", StringComparison.Ordinal);
        ulong magnitude;
        if (text.StartsWith("0x", StringComparison.Ordinal))
        {
            magnitude = ulong.Parse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }
        else if (text.StartsWith("0b", StringComparison.Ordinal))
        {
            magnitude = Convert.ToUInt64(text[2..], 2);
        }
        else if (text.Length > 1 && text[0] == '0')
        {
            magnitude = Convert.ToUInt64(text[1..], 8);
        }
        else
        {
            magnitude = 0;
            foreach (var part in text.Split(':'))
            {
                magnitude = checked(magnitude * 60 + ulong.Parse(part, CultureInfo.InvariantCulture));
            }
        }

        var signed = checked((long)magnitude);
        return checked((int)(negative ? -signed : signed));
    }

    private static bool IsNull(YamlNode node)
    {
        return node is YamlScalarNode scalar &&
               (scalar.Tag == "tag:yaml.org,2002:null" ||
                scalar.Tag.IsEmpty && scalar.Style == ScalarStyle.Plain &&
                (string.IsNullOrEmpty(scalar.Value) || scalar.Value == "~" ||
                 string.Equals(scalar.Value, "null", StringComparison.OrdinalIgnoreCase)));
    }
}