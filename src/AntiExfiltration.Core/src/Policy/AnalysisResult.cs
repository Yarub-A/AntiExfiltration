using System.Collections.Generic;
using AntiExfiltration.Core.Common;
using AntiExfiltration.Core.Context;

namespace AntiExfiltration.Core.Policy;

/// <summary>
/// Represents the enrichment and verdict produced by the policy engine.
/// </summary>
public sealed class AnalysisResult
{
    public required bool IsSensitive { get; init; }
    public required RiskLevel Risk { get; init; }
    public required string Reason { get; init; }
    public required IReadOnlyDictionary<string, object?> Signals { get; init; }
    public required IReadOnlyList<AnalyzerFinding> Findings { get; init; }
    public required ProcessInfo Process { get; init; }
}
