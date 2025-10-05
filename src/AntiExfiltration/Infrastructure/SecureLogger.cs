using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AntiExfiltration.Infrastructure;

public sealed class SecureLogger : IDisposable
{
    private const string KeyFileName = "log.key";

    private readonly string _logDirectory;
    private readonly byte[] _encryptionKey;
    private readonly ConcurrentQueue<string> _queue = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _writerTask;

    public SecureLogger(string logDirectory)
    {
        _logDirectory = logDirectory;
        Directory.CreateDirectory(_logDirectory);
        _encryptionKey = DeriveKey();
        _writerTask = Task.Run(() => ProcessQueueAsync(_cts.Token));
    }

    public void Log(object payload)
    {
        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        _queue.Enqueue(json);
    }

    private async Task ProcessQueueAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            if (!_queue.TryDequeue(out var entry))
            {
                await Task.Delay(100, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                var encrypted = Encrypt(entry);
                var fileName = Path.Combine(_logDirectory, $"log-{DateTime.UtcNow:yyyyMMdd}.bin");
                await File.AppendAllTextAsync(fileName, Convert.ToBase64String(encrypted) + Environment.NewLine, token)
                    .ConfigureAwait(false);
            }
            catch
            {
                // intentionally swallowed to maintain logging path; corrupted entries are ignored
            }
        }
    }

    private byte[] Encrypt(string text)
    {
        using var aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.GenerateIV();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        var plaintext = Encoding.UTF8.GetBytes(text);
        var ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        var result = new byte[aes.IV.Length + ciphertext.Length];
        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
        Buffer.BlockCopy(ciphertext, 0, result, aes.IV.Length, ciphertext.Length);
        return result;
    }

    private static byte[] DeriveKey()
    {
        var keyPath = Path.Combine(_logDirectory, KeyFileName);

        try
        {
            var protectedBytes = LoadOrCreateProtectedKey(keyPath);
            var unprotected = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);

            if (unprotected.Length == 32)
            {
                return unprotected;
            }

            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(unprotected);
        }
        catch
        {
            var recovery = RandomNumberGenerator.GetBytes(32);
            var protectedRecovery = ProtectedData.Protect(recovery, null, DataProtectionScope.CurrentUser);
            try
            {
                File.WriteAllBytes(keyPath, protectedRecovery);
            }
            catch
            {
                // ignore write failures; fall back to in-memory key only
            }

            return recovery;
        }
    }

    private static byte[] LoadOrCreateProtectedKey(string path)
    {
        if (File.Exists(path))
        {
            return File.ReadAllBytes(path);
        }

        var keyMaterial = RandomNumberGenerator.GetBytes(32);
        var protectedKey = ProtectedData.Protect(keyMaterial, null, DataProtectionScope.CurrentUser);

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, protectedKey);

        try
        {
            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Hidden);
        }
        catch
        {
            // best effort; ignore attribute failures
        }

        return protectedKey;
    }

    public void Dispose()
    {
        _cts.Cancel();
        try
        {
            _writerTask.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // ignore cancellation exceptions
        }

        _cts.Dispose();
    }
}
