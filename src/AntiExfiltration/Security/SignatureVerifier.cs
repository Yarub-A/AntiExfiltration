using System.Security.Cryptography.X509Certificates;

namespace AntiExfiltration.Security;

public static class SignatureVerifier
{
    public static bool IsSigned(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            return false;
        }

        try
        {
            using var signer = X509Certificate.CreateFromSignedFile(path);
            return signer != null;
        }
        catch
        {
            return false;
        }
    }
}
