using System;

namespace AntiExfiltration.Core.Capture;

/// <summary>
/// Event arguments emitted when the capture provider intercepts a packet.
/// </summary>
public sealed class PacketCapturedEventArgs : EventArgs
{
    public PacketCapturedEventArgs(RawPacket packet)
    {
        Packet = packet;
    }

    public RawPacket Packet { get; }
}
