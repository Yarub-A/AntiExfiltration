using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using AntiExfiltrationSystem.Utilities;

namespace AntiExfiltrationSystem.ReverseProxy;

public sealed record ClientHelloInfo(string? HostName, Stream PrefetchedStream, int ProcessId, IPEndPoint RemoteEndpoint);

[SupportedOSPlatform("windows")]
public static class TlsHelloReader
{
    public static async Task<ClientHelloInfo?> ReadClientHelloAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var baseStream = client.GetStream();
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            var bytesRead = await FillAsync(baseStream, buffer, cancellationToken).ConfigureAwait(false);
            if (bytesRead <= 0)
                return null;

            // Copy prefetched TLS ClientHello bytes to a safe buffer
            var prefetch = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, prefetch, 0, bytesRead);

            // Parse SNI hostname
            var hostName = ParseServerName(prefetch.AsSpan());
            var preloaded = new PreloadedStream(prefetch, baseStream);

            // Map connection to originating process
            var remote = (IPEndPoint)client.Client.RemoteEndPoint!;
            var local = (IPEndPoint)client.Client.LocalEndPoint!;
            var processId = SocketProcessMapper.ResolveProcessId(remote, local);

            return new ClientHelloInfo(hostName, preloaded, processId, remote);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static string? ParseServerName(ReadOnlySpan<byte> clientHello)
    {
        if (clientHello.Length < 5 || clientHello[0] != 0x16)
            return null;

        var pointer = 5 + 1 + 2 + 32;
        if (clientHello.Length < pointer + 1)
            return null;

        var sessionIdLength = clientHello[pointer];
        pointer += 1 + sessionIdLength;
        if (clientHello.Length < pointer + 2)
            return null;

        var cipherSuiteLength = (clientHello[pointer] << 8) + clientHello[pointer + 1];
        pointer += 2 + cipherSuiteLength;
        if (clientHello.Length < pointer + 1)
            return null;

        var compressionMethods = clientHello[pointer];
        pointer += 1 + compressionMethods;
        if (clientHello.Length < pointer + 2)
            return null;

        var extensionsLength = (clientHello[pointer] << 8) + clientHello[pointer + 1];
        pointer += 2;
        var end = pointer + extensionsLength;
        if (clientHello.Length < end)
            return null;

        while (pointer + 4 <= end)
        {
            var extensionType = (clientHello[pointer] << 8) + clientHello[pointer + 1];
            var extensionLength = (clientHello[pointer + 2] << 8) + clientHello[pointer + 3];
            pointer += 4;

            if (extensionType == 0) // SNI extension
            {
                var serverNameListLength = (clientHello[pointer] << 8) + clientHello[pointer + 1];
                if (serverNameListLength <= 0)
                    break;

                var serverNameType = clientHello[pointer + 2];
                var hostLength = (clientHello[pointer + 3] << 8) + clientHello[pointer + 4];
                if (serverNameType == 0 && pointer + 5 + hostLength <= end)
                    return Encoding.ASCII.GetString(clientHello.Slice(pointer + 5, hostLength));
            }

            pointer += extensionLength;
        }

        return null;
    }

    private static async Task<int> FillAsync(NetworkStream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
                break;

            offset += read;
            if (offset >= 5)
            {
                var length = (buffer[3] << 8) + buffer[4] + 5;
                if (offset >= length)
                    return length;
            }
        }

        return offset;
    }
}

internal sealed class PreloadedStream : Stream
{
    private readonly byte[] _prefetch;
    private readonly Stream _inner;
    private int _position;

    public PreloadedStream(byte[] prefetch, Stream inner)
    {
        _prefetch = prefetch;
        _inner = inner;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => _position; set => throw new NotSupportedException(); }

    public override void Flush() => _inner.Flush();

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_position < _prefetch.Length)
        {
            var toCopy = Math.Min(count, _prefetch.Length - _position);
            Array.Copy(_prefetch, _position, buffer, offset, toCopy);
            _position += toCopy;
            return toCopy;
        }

        return _inner.Read(buffer, offset, count);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_position < _prefetch.Length)
        {
            var toCopy = Math.Min(buffer.Length, _prefetch.Length - _position);
            _prefetch.AsMemory(_position, toCopy).CopyTo(buffer);
            _position += toCopy;
            return toCopy;
        }

        return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        _inner.Write(buffer, offset, count);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _inner.WriteAsync(buffer, offset, count, cancellationToken);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        _inner.WriteAsync(buffer, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _inner.Dispose();

        base.Dispose(disposing);
    }
}
