using AntiExfiltrationSystem.Detection;

namespace AntiExfiltrationSystem.Networking;

public interface INetworkMonitor : IAsyncDisposable
{
    event EventHandler<PacketCapturedEventArgs>? PacketCaptured;
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync();
}

public sealed class PacketCapturedEventArgs : EventArgs
{
    public required byte[] Payload { get; init; }
    public required int ProcessId { get; init; }
    public required string Protocol { get; init; }
    public required System.Net.IPEndPoint RemoteEndpoint { get; init; }
}
