using FrpBan.Client.Matching;

namespace FrpBan.Client.Configuration;

internal static class RuleValidator
{
    public static string? Validate(BanRule rule)
    {
        if (string.IsNullOrWhiteSpace(rule.Name))
        {
            return "Rule name is required.";
        }

        if (rule.LogSource is null || rule.LogSource.Type is not ("file" or "journal"))
        {
            return "A log source of type 'file' or 'journal' is required.";
        }

        if (rule.LogSource.Type == "file" && string.IsNullOrWhiteSpace(rule.LogSource.Path))
        {
            return "A file log source requires a path.";
        }

        if (rule.LogSource.Type == "journal" &&
            (string.IsNullOrWhiteSpace(rule.LogSource.Service) || rule.LogSource.Service.Contains('\0')))
        {
            return "A journal log source requires a service name without null characters.";
        }

        if (rule.Matching is not { Count: > 0 } || rule.Matching.Count > 100)
        {
            return "Rules require between 1 and 100 matching expressions.";
        }

        if (rule.Action is null || rule.Action.Type is not ("immediate" or "threshold") ||
            rule.Action.BanDurationSeconds < 0 || rule.Action.MaxMatches is < 1 or > 10000 ||
            rule.Action.WindowSeconds is < 1 or > 86400 || rule.MaxTrackedIps is < 1 or > 100000 ||
            rule.Action.Reason is null || rule.Action.Reason.Length > 1024)
        {
            return "Invalid action, threshold, duration, or state limits.";
        }

        foreach (var expression in rule.Matching)
        {
            if (expression is null)
            {
                return "Matching expressions cannot be null.";
            }

            if (expression.Type == "regex")
            {
                if (string.IsNullOrWhiteSpace(expression.Pattern) || expression.Pattern.Length > 4096)
                {
                    return "Regex patterns must contain between 1 and 4096 characters.";
                }

                try
                {
                    if (!RuleRegex.Get(expression).GetGroupNames().Contains("ip", StringComparer.Ordinal))
                    {
                        return "Regex patterns require a named group (?<ip>...).";
                    }
                }
                catch (ArgumentException ex)
                {
                    return $"Invalid regex: {ex.Message}";
                }
            }
            else if (expression.Type != "json" || string.IsNullOrWhiteSpace(expression.JsonPath))
            {
                return "Expressions require a regex pattern or JSON field path.";
            }
        }

        return null;
    }
}