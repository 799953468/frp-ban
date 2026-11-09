using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using FrpBan.Client.Configuration;

namespace FrpBan.Client.Matching;

internal static class RuleRegex
{
    private static readonly ConditionalWeakTable<MatchExpression, Lazy<Regex>> Cache = new();

    public static Regex Get(MatchExpression expression) => Cache.GetValue(expression,
        key => new Lazy<Regex>(() => new Regex(key.Pattern!, RegexOptions.Compiled | RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(100)))).Value;
}
