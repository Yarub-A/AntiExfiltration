using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using AntiExfiltrationSystem.Utilities;

namespace AntiExfiltrationSystem.ReverseProxy;

public sealed class ProductionReverseProxy : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CertificateAuthority _certificateAuthority;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _workers = new();
    private X509Certificate2? _rootCertificate;

    public event EventHandler<DecryptedPayloadEventArgs>? PayloadReady;

    public ProductionReverseProxy(int listeningPort = 8443)
    {
        _listener = new TcpListener(IPAddress.Any, listeningPort);
        _certificateAuthority = new CertificateAuthority();
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        EnsureAdministrator();
        _rootCertificate = _certificateAuthority.LoadOrCreateRootCertificate();
        _listener.Start();
        _workers.Add(Task.Run(() => AcceptLoopAsync(cancellationToken), cancellationToken));
        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && !_cts.IsCancellationRequested)
        {
            var client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            _workers.Add(Task.Run(() => HandleClientAsync(client, cancellationToken), cancellationToken));
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            var clientHello = await TlsHelloReader.ReadClientHelloAsync(client, cancellationToken).ConfigureAwait(false);
            if (clientHello is null)
            {
                return;
            }

            var hostName = clientHello.HostName ?? throw new InvalidOperationException("Client hello did not contain a server name indication.");
            using var remote = new TcpClient();
            await remote.ConnectAsync(hostName, 443, cancellationToken).ConfigureAwait(false);

            using var clientSsl = new SslStream(clientHello.PrefetchedStream, false);
            using var remoteSsl = new SslStream(remote.GetStream(), false, (sender, certificate, chain, errors) => true);

            var serverCert = _certificateAuthority.CreateServerCertificate(hostName, _rootCertificate!);
            await clientSsl.AuthenticateAsServerAsync(serverCert, false, SslProtocols.Tls13 | SslProtocols.Tls12, false).ConfigureAwait(false);

            await remoteSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = hostName,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, cancellationToken).ConfigureAwait(false);

            var inspector = new PayloadMirrorStream(remoteSsl, data =>
            {
                PayloadReady?.Invoke(this, new DecryptedPayloadEventArgs
                {
                    Payload = data,
                    Host = hostName,
                    ProcessId = clientHello.ProcessId,
                    RemoteEndpoint = (IPEndPoint)remote.Client.RemoteEndPoint!
                });
            });

            var downstream = inspector.StartMirroringAsync(clientSsl, cancellationToken);
            var upstream = inspector.StartReverseMirroringAsync(clientSsl, cancellationToken);
            await Task.WhenAll(downstream, upstream).ConfigureAwait(false);
        }
    }

    public async Task StopAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        await Task.WhenAll(_workers).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _cts.Dispose();
        foreach (var worker in _workers)
        {
            worker.Dispose();
        }
    }

    private static void EnsureAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The interception engine requires Windows.");
        }

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new UnauthorizedAccessException("Administrator privileges are required.");
        }
    }
}
