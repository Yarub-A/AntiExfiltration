using System;
using System.Net;

namespace AntiExfiltration.Core.Capture;

/// <summary>
/// Represents the immutable raw packet information captured from the network stack.
/// </summary>
public sealed record RawPacket(
    byte[] Payload,
    IPEndPoint Source,
    IPEndPoint Destination,
    ProtocolType Protocol,
    int ProcessId,
    DateTimeOffset Timestamp);

/// <summary>
/// Simplified protocol enumeration to avoid System.Net.Sockets dependency in core abstractions.
/// </summary>
public enum ProtocolType
{
    Tcp,
    Udp,
    Dns,
    Http,
    Https,
    WebSocket,
    Unknown
}
