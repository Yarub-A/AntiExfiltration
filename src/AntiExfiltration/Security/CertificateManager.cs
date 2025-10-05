using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;

namespace AntiExfiltration.Security;

[SupportedOSPlatform("windows")]
public sealed class CertificateManager
{
    private readonly SecureLogger _logger;
    private readonly CertificateConfiguration _configuration;

    public CertificateManager(SecureLogger logger, CertificateConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public void Initialize()
    {
        var storeLocation = _configuration.InstallToLocalMachine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
        using var store = new X509Store(StoreName.Root, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        var existing = store.Certificates.Cast<X509Certificate2>().FirstOrDefault(cert => cert.FriendlyName == _configuration.CertificateFriendlyName);
        if (existing != null)
        {
            return;
        }

        var certificate = GenerateCertificate();
        store.Add(certificate);

        _logger.Log(new
        {
            timestamp = DateTimeOffset.UtcNow,
            eventType = "certificateInstalled",
            certificate.Subject,
            storeLocation = storeLocation.ToString()
        });
    }

    private X509Certificate2 GenerateCertificate()
    {
        using var rsa = RSA.Create(4096);
        var request = new CertificateRequest(
            new X500DistinguishedName($"CN={_configuration.CertificateFriendlyName}"),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        certificate.FriendlyName = _configuration.CertificateFriendlyName;
        return certificate;
    }
}
