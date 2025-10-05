using AntiExfiltration.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AntiExfiltration.Infrastructure;

public static class LogDecoder
{
    public static int DecodeToConsole(string logFilePath)
    {
        try
        {
            foreach (var line in DecodeLines(logFilePath))
            {
                Console.WriteLine(line);
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    public static IReadOnlyList<string> DecodeLines(string logFilePath)
    {
        var key = LoadKeyMaterial(logFilePath, out _);
        var results = new List<string>();
        var index = 0;

        foreach (var line in File.ReadLines(logFilePath))
        {
            index++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                results.Add(DecryptLine(line.Trim(), key));
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                results.Add($"<line {index}: decryption failed - {ex.Message}>");
            }
        }

        return results;
    }

    public static IReadOnlyList<LoadSample> DecodeRuntimeLoad(string logFilePath)
    {
        var key = LoadKeyMaterial(logFilePath, out _);
        var samples = new List<LoadSample>();

        foreach (var line in File.ReadLines(logFilePath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                var json = DecryptLine(line.Trim(), key);
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement;
                if (!root.TryGetProperty("eventType", out var eventType) || eventType.GetString() != "runtimeLoad")
                {
                    continue;
                }

                var sample = new LoadSample
                {
                    Timestamp = root.GetProperty("timestamp").GetDateTimeOffset(),
                    CpuPercent = root.GetProperty("cpuPercent").GetDouble(),
                    WorkingSetMb = root.GetProperty("workingSetMb").GetDouble(),
                    ManagedMemoryMb = root.GetProperty("managedMemoryMb").GetDouble(),
                    ThreadCount = root.GetProperty("threadCount").GetInt64(),
                    HandleCount = root.GetProperty("handleCount").GetInt64(),
                    NetworkBytesPerSecond = TryReadNullableDouble(root, "networkBytesPerSecond")
                };

                samples.Add(sample);
            }
            catch
            {
                // ignore malformed entries
            }
        }

        return samples;
    }

    private static double? TryReadNullableDouble(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.Number => value.GetDouble(),
            JsonValueKind.String when double.TryParse(value.GetString(), out var parsed) => parsed,
            _ => null
        };
    }

    private static byte[] LoadKeyMaterial(string logFilePath, out string directory)
    {
        if (string.IsNullOrWhiteSpace(logFilePath))
        {
            throw new ArgumentException("The supplied log file path is empty.", nameof(logFilePath));
        }

        if (!File.Exists(logFilePath))
        {
            throw new FileNotFoundException($"Log file not found: {logFilePath}", logFilePath);
        }

        directory = Path.GetDirectoryName(Path.GetFullPath(logFilePath)) ?? Environment.CurrentDirectory;
        var keyPath = Path.Combine(directory, "log.key");
        if (!File.Exists(keyPath))
        {
            throw new InvalidOperationException($"Protected key file (log.key) was not found next to {logFilePath}. Run the decoder on the same machine and Windows account that generated the logs.");
        }

        try
        {
            var protectedKey = File.ReadAllBytes(keyPath);
            var unprotected = ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.CurrentUser);
            if (unprotected.Length == 32)
            {
                return unprotected;
            }

            using var sha = SHA256.Create();
            return sha.ComputeHash(unprotected);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("Failed to unprotect the key using DPAPI. Use the same Windows account that executed AntiExfiltration.", ex);
        }
    }

    private static string DecryptLine(string line, byte[] key)
    {
        var decoded = Convert.FromBase64String(line);
        if (decoded.Length <= 16)
        {
            throw new CryptographicException("Entry shorter than IV + ciphertext.");
        }

        var iv = decoded.AsSpan(0, 16).ToArray();
        var cipher = decoded.AsSpan(16).ToArray();

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        var plaintext = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
        return Encoding.UTF8.GetString(plaintext);
    }
}
