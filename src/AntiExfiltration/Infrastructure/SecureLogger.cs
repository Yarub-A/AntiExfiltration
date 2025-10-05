using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AntiExfiltration.Infrastructure;

public sealed class SecureLogger : IDisposable
{
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
        var entropy = Encoding.UTF8.GetBytes("AntiExfiltrationLogKey");
        var keyMaterial = ProtectedData.Protect(entropy, null, DataProtectionScope.CurrentUser);
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(keyMaterial);
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
