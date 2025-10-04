using System.Text.RegularExpressions;

namespace AntiExfiltrationSystem.Utilities;

public static class SensitiveDataDetector
{
    private static readonly Regex[] Patterns =
    {
        new(@"\b4[0-9]{12}(?:[0-9]{3})?\b", RegexOptions.Compiled),
        new(@"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", RegexOptions.Compiled),
        new(@"password\s*[:=]\s*[^\s]+", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"AWS_SECRET_ACCESS_KEY\s*=\s*[A-Za-z0-9/+=]{40}", RegexOptions.Compiled),
        new(@"AKIA[0-9A-Z]{16}", RegexOptions.Compiled)
    };

    public static bool IsSensitive(string value)
    {
        foreach (var pattern in Patterns)
        {
            if (pattern.IsMatch(value))
            {
                return true;
            }
        }

        return value.Length > 64 && value.Any(char.IsLetter) && value.Any(char.IsDigit);
    }
}
