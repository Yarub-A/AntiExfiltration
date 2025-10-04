using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AntiExfiltrationSystem.ReverseProxy;

public sealed class CertificateAuthority
{
    private const string CertificateFriendlyName = "AntiExfiltration Root CA";

    public X509Certificate2 LoadOrCreateRootCertificate()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        var existing = store.Certificates
            .Cast<X509Certificate2>()
            .FirstOrDefault(cert => cert.FriendlyName == CertificateFriendlyName);

        if (existing is not null)
        {
            return existing;
        }

        using var rsa = RSA.Create(4096);
        var request = new CertificateRequest(
            "CN=AntiExfiltration Root CA",
            rsa,
            HashAlgorithmName.SHA512,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        certificate.FriendlyName = CertificateFriendlyName;
        store.Add(certificate);
        return certificate;
    }

    public X509Certificate2 CreateServerCertificate(string hostName, X509Certificate2 issuer)
    {
        using var rsa = RSA.Create(4096);
        var request = new CertificateRequest($"CN={hostName}", rsa, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(hostName);
        request.CertificateExtensions.Add(sanBuilder.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));

        var certificate = request.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2), Guid.NewGuid().ToByteArray());
        return certificate.CopyWithPrivateKey(rsa);
    }
}
