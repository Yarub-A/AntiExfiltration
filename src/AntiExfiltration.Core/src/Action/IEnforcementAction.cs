using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Common;
using AntiExfiltration.Core.Context;

namespace AntiExfiltration.Core.Action;

/// <summary>
/// Contract for executing the final enforcement step once a decision is produced.
/// </summary>
public interface IEnforcementAction
{
    void Execute(Decision decision, RawPacket packet, ProcessInfo process, CancellationToken cancellationToken = default);
}
