using System.Net.Security;

namespace AntiExfiltrationSystem.ReverseProxy;

public sealed class PayloadMirrorStream
{
    private readonly SslStream _remoteStream;
    private readonly Action<byte[]> _onPayload;

    public PayloadMirrorStream(SslStream remoteStream, Action<byte[]> onPayload)
    {
        _remoteStream = remoteStream;
        _onPayload = onPayload;
    }

    public async Task StartMirroringAsync(SslStream clientStream, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        while (!cancellationToken.IsCancellationRequested)
        {
            var bytesRead = await _remoteStream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (bytesRead <= 0)
            {
                break;
            }

            var payload = buffer[..bytesRead].ToArray();
            _onPayload(payload);
            await clientStream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task StartReverseMirroringAsync(SslStream clientStream, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        while (!cancellationToken.IsCancellationRequested)
        {
            var bytesRead = await clientStream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (bytesRead <= 0)
            {
                break;
            }

            var payload = buffer[..bytesRead].ToArray();
            _onPayload(payload);
            await _remoteStream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }
    }
}
