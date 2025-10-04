using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AntiExfiltrationSystem.Memory;
using AntiExfiltrationSystem.ProcessMonitoring;
using AntiExfiltrationSystem.Utilities;
using AntiExfiltrationSystem.ThreatIntel;

namespace AntiExfiltrationSystem.Detection;

public sealed class PayloadAnalyzer
{
    private static readonly Regex JsonPattern = new(@"\{\s*\"[A-Za-z0-9_]+\"\s*:", RegexOptions.Compiled);
    private static readonly Regex SqlPattern = new(@"(SELECT|INSERT|UPDATE|DELETE)\s+[A-Z0-9_]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private readonly ThreatIntelCenter _intelCenter = new();

    public PayloadAnalysisResult Inspect(byte[] payload, ProcessContext context)
    {
        var text = Encoding.UTF8.GetString(payload);
        var entropy = CalculateEntropy(payload);
        var indicators = new List<string>();

        if (JsonPattern.IsMatch(text))
        {
            indicators.Add("JSON structure detected");
        }

        if (SqlPattern.IsMatch(text))
        {
            indicators.Add("SQL export pattern");
        }

        if (SensitiveDataDetector.IsSensitive(text))
        {
            indicators.Add("Sensitive data signature");
        }

        if (entropy > 7.5)
        {
            indicators.Add("High entropy payload");
        }

        indicators.AddRange(_intelCenter.MatchIndicators(text));

        var hash = Convert.ToHexString(SHA256.HashData(payload));
        return new PayloadAnalysisResult
        {
            Entropy = entropy,
            Indicators = indicators,
            ContentHash = hash,
            Context = context
        };
    }

    private static double CalculateEntropy(IReadOnlyList<byte> data)
    {
        var counts = new int[256];
        foreach (var b in data)
        {
            counts[b]++;
        }

        double entropy = 0;
        var length = data.Count;
        for (var i = 0; i < counts.Length; i++)
        {
            if (counts[i] == 0)
            {
                continue;
            }

            var probability = counts[i] / (double)length;
            entropy -= probability * Math.Log(probability, 2);
        }

        return entropy;
    }
}

public sealed class PayloadAnalysisResult
{
    public required double Entropy { get; init; }
    public required IReadOnlyList<string> Indicators { get; init; }
    public required string ContentHash { get; init; }
    public required ProcessContext Context { get; init; }
}
