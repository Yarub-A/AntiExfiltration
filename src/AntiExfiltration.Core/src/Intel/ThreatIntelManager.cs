using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AntiExfiltration.Core.Capture;

namespace AntiExfiltration.Core.Intel;

/// <summary>
/// Basic in-memory implementation that consumes IOC indicators provided at runtime.
/// </summary>
public sealed class ThreatIntelManager : IThreatIntelProvider
{
    private readonly HashSet<string> _maliciousDestinations = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _keywordIndicators = new(StringComparer.OrdinalIgnoreCase);

    public void LoadDestinations(IEnumerable<string> destinations)
    {
        _maliciousDestinations.Clear();
        foreach (var destination in destinations)
        {
            _maliciousDestinations.Add(destination);
        }
    }

    public void LoadKeywords(IEnumerable<string> keywords)
    {
        _keywordIndicators.Clear();
        foreach (var keyword in keywords)
        {
            _keywordIndicators.Add(keyword);
        }
    }

    public ValueTask RefreshAsync(CancellationToken cancellationToken = default)
    {
        // Placeholder for pulling remote feeds.
        return ValueTask.CompletedTask;
    }

    public bool IsMalicious(RawPacket packet)
    {
        if (_maliciousDestinations.Contains(packet.Destination.Address.ToString()))
        {
            return true;
        }

        var payloadText = System.Text.Encoding.UTF8.GetString(packet.Payload);
        return _keywordIndicators.Any(keyword => payloadText.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }
}
