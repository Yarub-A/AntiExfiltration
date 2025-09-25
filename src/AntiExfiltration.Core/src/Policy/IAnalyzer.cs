using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Context;

namespace AntiExfiltration.Core.Policy;

/// <summary>
/// Defines a detection component that inspects outbound packets to surface sensitive content.
/// </summary>
public interface IAnalyzer
{
    AnalyzerFinding Analyze(RawPacket packet, ProcessInfo process);
}
