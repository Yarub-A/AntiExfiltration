using System.Collections.Generic;
using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Context;

namespace AntiExfiltration.Core.Policy;

/// <summary>
/// Coordinates different analyzers (signatures, entropy, behavior) to evaluate packets.
/// </summary>
public sealed class PolicyEngine
{
    private readonly IEnumerable<IAnalyzer> _analyzers;
    private readonly IProcessContextResolver _contextResolver;

    public PolicyEngine(IEnumerable<IAnalyzer> analyzers, IProcessContextResolver contextResolver)
    {
        _analyzers = analyzers;
        _contextResolver = contextResolver;
    }

    public AnalysisResult Analyze(RawPacket packet)
    {
        var process = _contextResolver.Resolve(packet.ProcessId);
        var findings = new List<AnalyzerFinding>();
        var aggregatedSignals = new Dictionary<string, object?>();

        var highestRisk = Common.RiskLevel.Low;
        var primaryReason = "No analyzer detected sensitive content";
        var sensitiveDetected = false;

        foreach (var analyzer in _analyzers)
        {
            var finding = analyzer.Analyze(packet, process);
            findings.Add(finding);

            foreach (var kvp in finding.Signals)
            {
                var namespacedKey = $"{finding.Analyzer}.{kvp.Key}";
                aggregatedSignals[namespacedKey] = kvp.Value;
            }

            if (!finding.IsSensitive)
            {
                continue;
            }

            sensitiveDetected = true;
            if (finding.Risk >= highestRisk)
            {
                highestRisk = finding.Risk;
                primaryReason = finding.Reason;
            }
        }

        return new AnalysisResult
        {
            IsSensitive = sensitiveDetected,
            Risk = sensitiveDetected ? highestRisk : Common.RiskLevel.Low,
            Reason = primaryReason,
            Signals = aggregatedSignals,
            Findings = findings,
            Process = process
        };
    }
}
