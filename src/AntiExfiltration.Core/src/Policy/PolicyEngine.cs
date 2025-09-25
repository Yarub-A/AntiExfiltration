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
        foreach (var analyzer in _analyzers)
        {
            var result = analyzer.Analyze(packet);
            if (result.IsSensitive)
            {
                return result with { Process = process };
            }
        }

        return new AnalysisResult
        {
            IsSensitive = false,
            Risk = Common.RiskLevel.Low,
            Reason = "No analyzer matched",
            Signals = new Dictionary<string, object?>(),
            Process = process
        };
    }
}
