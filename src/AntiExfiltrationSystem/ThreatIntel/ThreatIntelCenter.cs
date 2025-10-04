using System.Text.RegularExpressions;

namespace AntiExfiltrationSystem.ThreatIntel;

public sealed class ThreatIntelCenter
{
    private readonly List<ThreatPattern> _iocPatterns =
    [
        new(new Regex(@"(?:login|auth)[^\n]{0,20}(?:failed|error)", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Authentication failure indicator"),
        new(new Regex(@"(?:rsa|dsa)_private_key", RegexOptions.IgnoreCase | RegexOptions.Compiled), "Private key token"),
        new(new Regex(@"-----BEGIN PRIVATE KEY-----", RegexOptions.Compiled), "PEM private key block")
    ];

    public IReadOnlyList<string> MatchIndicators(string content)
    {
        var matches = new List<string>();
        foreach (var pattern in _iocPatterns)
        {
            if (pattern.Pattern.IsMatch(content))
            {
                matches.Add(pattern.Description);
            }
        }

        return matches;
    }
}

internal readonly record struct ThreatPattern(Regex Pattern, string Description);
