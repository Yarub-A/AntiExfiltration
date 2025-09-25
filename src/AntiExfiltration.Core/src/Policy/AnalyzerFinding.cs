using System.Collections.Generic;
using AntiExfiltration.Core.Common;
using AntiExfiltration.Core.Context;

namespace AntiExfiltration.Core.Policy;

/// <summary>
/// Represents the decision of a single analyzer, including contextual evidence.
/// </summary>
public sealed record AnalyzerFinding(
    string Analyzer,
    bool IsSensitive,
    RiskLevel Risk,
    string Reason,
    IReadOnlyDictionary<string, object?> Signals,
    ProcessInfo Process);
