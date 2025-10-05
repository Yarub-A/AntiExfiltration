using System.Security.Cryptography;
using System.Text;

namespace AntiExfiltration.Infrastructure;

public static class LogDecoder
{
    public static int DecodeToConsole(string logFilePath)
    {
        if (string.IsNullOrWhiteSpace(logFilePath))
        {
            Console.Error.WriteLine("مسار ملف السجل غير صالح.");
            return 1;
        }

        if (!File.Exists(logFilePath))
        {
            Console.Error.WriteLine($"تعذر العثور على ملف السجل: {logFilePath}");
            return 1;
        }

        var directory = Path.GetDirectoryName(Path.GetFullPath(logFilePath)) ?? Environment.CurrentDirectory;
        var keyPath = Path.Combine(directory, "log.key");
        if (!File.Exists(keyPath))
        {
            Console.Error.WriteLine($"تعذر العثور على ملف المفتاح المحمي (log.key) بجوار {logFilePath}.");
            Console.Error.WriteLine("تأكد أنك تشغّل الأمر على نفس الجهاز وبنفس الحساب الذي أنشأ السجلات.");
            return 1;
        }

        byte[] keyMaterial;
        try
        {
            var protectedKey = File.ReadAllBytes(keyPath);
            keyMaterial = ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.CurrentUser);
            if (keyMaterial.Length != 32)
            {
                using var sha = SHA256.Create();
                keyMaterial = sha.ComputeHash(keyMaterial);
            }
        }
        catch (CryptographicException ex)
        {
            Console.Error.WriteLine("فشل فك حماية المفتاح عبر DPAPI. استخدم نفس حساب Windows الذي قام بتشغيل AntiExfiltration.");
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        var lines = File.ReadLines(logFilePath);
        var index = 0;
        foreach (var line in lines)
        {
            index++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                var decoded = Convert.FromBase64String(line.Trim());
                if (decoded.Length <= 16)
                {
                    Console.Error.WriteLine($"سطر {index}: بيانات غير كافية بعد فك Base64.");
                    continue;
                }

                var iv = decoded.AsSpan(0, 16).ToArray();
                var cipher = decoded.AsSpan(16).ToArray();

                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = keyMaterial;
                aes.IV = iv;

                using var decryptor = aes.CreateDecryptor();
                var plaintext = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
                Console.WriteLine(Encoding.UTF8.GetString(plaintext));
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                Console.Error.WriteLine($"سطر {index}: فشل فك التشفير - {ex.Message}");
            }
        }

        return 0;
    }
}
