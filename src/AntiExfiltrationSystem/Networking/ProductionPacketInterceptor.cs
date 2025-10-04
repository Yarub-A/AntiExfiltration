using System.Buffers;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security;
using AntiExfiltrationSystem.Utilities;

namespace AntiExfiltrationSystem.Networking;

[SupportedOSPlatform("windows")]
public sealed class ProductionPacketInterceptor : INetworkMonitor
{
    private readonly NetworkInterface _adapter;
    private readonly Socket _socket;
    private readonly CancellationTokenSource _cts = new();
    private Task? _captureTask;

    public event EventHandler<PacketCapturedEventArgs>? PacketCaptured;

    public ProductionPacketInterceptor(NetworkInterface adapter)
    {
        _adapter = adapter;
        _socket = CreateCaptureSocket();
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _captureTask = Task.Run(() => CaptureLoopAsync(cancellationToken), cancellationToken);
        return Task.CompletedTask;
    }

    private async Task CaptureLoopAsync(CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(65535);
        try
        {
            while (!cancellationToken.IsCancellationRequested && !_cts.IsCancellationRequested)
            {
                var segment = new ArraySegment<byte>(buffer);
                var bytesRead = await _socket.ReceiveAsync(segment, SocketFlags.None, cancellationToken).ConfigureAwait(false);
                if (bytesRead <= 0)
                {
                    continue;
                }

                var payload = segment[..bytesRead];
                var remote = ParseRemoteEndpoint(payload);
                PacketCaptured?.Invoke(this, new PacketCapturedEventArgs
                {
                    Payload = payload.ToArray(),
                    ProcessId = TcpIpHelper.ResolveOwningProcess(remote),
                    Protocol = TcpIpHelper.DetectProtocol(payload),
                    RemoteEndpoint = remote
                });
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public async Task StopAsync()
    {
        _cts.Cancel();
        if (_captureTask is { } task)
        {
            await task.ConfigureAwait(false);
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _socket.Dispose();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }

    private Socket CreateCaptureSocket()
    {
        var ipProps = _adapter.GetIPProperties();
        var ipv4 = ipProps.UnicastAddresses.FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);
        if (ipv4 is null)
        {
            throw new SecurityException("Selected adapter does not expose a valid IPv4 address.");
        }

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP)
        {
            ReceiveTimeout = 1000
        };

        socket.Bind(new IPEndPoint(ipv4.Address, 0));
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);
        return socket;
    }

    private static IPEndPoint ParseRemoteEndpoint(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20)
        {
            return new IPEndPoint(IPAddress.None, 0);
        }

        var destAddress = new IPAddress(packet.Slice(16, 4));
        var protocol = packet[9];
        int destPort = 0;
        if (protocol is 6 or 17)
        {
            destPort = (packet[22] << 8) + packet[23];
        }

        return new IPEndPoint(destAddress, destPort);
    }
}
