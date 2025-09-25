using AntiExfiltration.Core.Common;
using AntiExfiltration.Core.Policy;

namespace AntiExfiltration.Core.Decision;

/// <summary>
/// Applies configurable policies to translate analysis results into enforcement decisions.
/// </summary>
public sealed class DecisionEngine
{
    private readonly DecisionEngineOptions _options;

    public DecisionEngine(DecisionEngineOptions options)
    {
        _options = options;
    }

    public Decision Decide(AnalysisResult analysis)
    {
        if (!analysis.IsSensitive)
        {
            return Decision.Allow;
        }

        return analysis.Risk switch
        {
            RiskLevel.Low => _options.LowRiskDecision,
            RiskLevel.Medium => _options.MediumRiskDecision,
            RiskLevel.High => _options.HighRiskDecision,
            _ => Decision.Alert
        };
    }
}

/// <summary>
/// Allows tuning of the default responses for each risk level.
/// </summary>
public sealed class DecisionEngineOptions
{
    public Decision LowRiskDecision { get; init; } = Decision.Alert;
    public Decision MediumRiskDecision { get; init; } = Decision.Obfuscate;
    public Decision HighRiskDecision { get; init; } = Decision.Block;
}
