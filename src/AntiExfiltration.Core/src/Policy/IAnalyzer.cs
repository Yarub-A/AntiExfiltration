using AntiExfiltration.Core.Capture;

namespace AntiExfiltration.Core.Policy;

/// <summary>
/// Defines a detection component that inspects outbound packets to surface sensitive content.
/// </summary>
public interface IAnalyzer
{
    AnalysisResult Analyze(RawPacket packet);
}
