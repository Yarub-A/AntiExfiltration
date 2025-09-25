using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Common;
using AntiExfiltration.Core.Context;
using AntiExfiltration.Core.Intel;

namespace AntiExfiltration.Core.Policy;

/// <summary>
/// Fast-path analyzer that inspects packets for known signatures (keywords, magic bytes, IOCs).
/// </summary>
public sealed class SignatureAnalyzer : IAnalyzer
{
    private static readonly Regex SensitiveKeywordRegex = new("(password|token|apikey|cookie|credential)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly IThreatIntelProvider _threatIntelProvider;
    public SignatureAnalyzer(IThreatIntelProvider threatIntelProvider)
    {
        _threatIntelProvider = threatIntelProvider;
    }

    public AnalyzerFinding Analyze(RawPacket packet, ProcessInfo process)
    {
        if (_threatIntelProvider.IsMalicious(packet))
        {
            return CreateHighRiskResult(packet, process, "IOC match");
        }

        var payloadString = Encoding.UTF8.GetString(packet.Payload);
        if (SensitiveKeywordRegex.IsMatch(payloadString))
        {
            return CreateMediumRiskResult(packet, process, "Sensitive keyword detected", payloadString);
        }

        return new AnalyzerFinding(
            Analyzer: nameof(SignatureAnalyzer),
            IsSensitive: false,
            Risk: RiskLevel.Low,
            Reason: "No signature hit",
            Signals: new Dictionary<string, object?>(),
            Process: process);
    }

    private static AnalyzerFinding CreateHighRiskResult(RawPacket packet, ProcessInfo process, string reason)
        => new(
            Analyzer: nameof(SignatureAnalyzer),
            IsSensitive: true,
            Risk: RiskLevel.High,
            Reason: reason,
            Signals: new Dictionary<string, object?>
            {
                ["Destination"] = packet.Destination.ToString(),
                ["Protocol"] = packet.Protocol.ToString()
            },
            Process: process);

    private static AnalyzerFinding CreateMediumRiskResult(RawPacket packet, ProcessInfo process, string reason, string excerpt)
        => new(
            Analyzer: nameof(SignatureAnalyzer),
            IsSensitive: true,
            Risk: RiskLevel.Medium,
            Reason: reason,
            Signals: new Dictionary<string, object?>
            {
                ["Excerpt"] = excerpt[..Math.Min(128, excerpt.Length)],
                ["Process"] = process.Name
            },
            Process: process);
}
