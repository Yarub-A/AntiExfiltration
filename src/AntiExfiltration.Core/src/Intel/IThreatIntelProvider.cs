using System.Threading;
using System.Threading.Tasks;
using AntiExfiltration.Core.Capture;

namespace AntiExfiltration.Core.Intel;

/// <summary>
/// Interface for external intelligence sources such as YARA, IOC feeds, or custom signatures.
/// </summary>
public interface IThreatIntelProvider
{
    ValueTask RefreshAsync(CancellationToken cancellationToken = default);
    bool IsMalicious(RawPacket packet);
}
