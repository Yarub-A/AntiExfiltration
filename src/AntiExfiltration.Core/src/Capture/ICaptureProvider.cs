using System;

namespace AntiExfiltration.Core.Capture;

/// <summary>
/// Abstraction responsible for tapping into outbound network traffic.
/// </summary>
public interface ICaptureProvider
{
    event EventHandler<PacketCapturedEventArgs>? PacketCaptured;

    /// <summary>
    /// Starts interception with elevated privileges.
    /// </summary>
    void Start();
}
