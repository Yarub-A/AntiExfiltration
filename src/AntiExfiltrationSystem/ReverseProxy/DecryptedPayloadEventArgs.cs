namespace AntiExfiltrationSystem.ReverseProxy;

public sealed class DecryptedPayloadEventArgs : EventArgs
{
    public required byte[] Payload { get; init; }
    public required string Host { get; init; }
    public required int ProcessId { get; init; }
    public required System.Net.IPEndPoint RemoteEndpoint { get; init; }
}
