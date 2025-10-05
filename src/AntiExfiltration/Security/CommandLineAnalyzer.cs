using System.Text.RegularExpressions;

namespace AntiExfiltration.Security;

public static class CommandLineAnalyzer
{
    private static readonly Regex Base64PowerShellRegex = new(@"(?i)powershell.+-e\s+[A-Za-z0-9+/=]+", RegexOptions.Compiled);
    private static readonly Regex MshtaRegex = new(@"(?i)mshta\s+", RegexOptions.Compiled);
    private static readonly Regex AutoItRegex = new(@"(?i)autoit.*\.au3", RegexOptions.Compiled);

    public static bool ContainsEncodedPowerShell(string commandLine)
        => Base64PowerShellRegex.IsMatch(commandLine);

    public static bool ContainsMshta(string commandLine)
        => MshtaRegex.IsMatch(commandLine);

    public static bool ContainsAutoIt(string commandLine)
        => AutoItRegex.IsMatch(commandLine);
}
