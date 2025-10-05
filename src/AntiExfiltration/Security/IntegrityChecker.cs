using AntiExfiltration.Infrastructure;
using System.Security.Cryptography;

namespace AntiExfiltration.Security;

public sealed class IntegrityChecker
{
    private readonly SecureLogger _logger;
    private readonly IntegrityConfiguration _configuration;
    private readonly Dictionary<string, byte[]> _checksums = new(StringComparer.OrdinalIgnoreCase);

    public IntegrityChecker(SecureLogger logger, IntegrityConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public async Task VerifyAsync(CancellationToken token)
    {
        foreach (var file in _configuration.ProtectedFiles)
        {
            var path = Path.Combine(AppContext.BaseDirectory, file);
            if (!File.Exists(path))
            {
                continue;
            }

            var checksum = await ComputeChecksumAsync(path, token).ConfigureAwait(false);
            _checksums[path] = checksum;
        }

        _ = Task.Run(() => WatchAsync(token), token);
    }

    private async Task WatchAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            foreach (var (path, baseline) in _checksums.ToList())
            {
                if (!File.Exists(path))
                {
                    continue;
                }

                var checksum = await ComputeChecksumAsync(path, token).ConfigureAwait(false);
                if (!checksum.SequenceEqual(baseline))
                {
                    _logger.Log(new
                    {
                        timestamp = DateTimeOffset.UtcNow,
                        eventType = "integrityViolation",
                        path
                    });
                }
            }

            await Task.Delay(_configuration.VerificationInterval, token).ConfigureAwait(false);
        }
    }

    private static async Task<byte[]> ComputeChecksumAsync(string path, CancellationToken token)
    {
        await using var stream = File.OpenRead(path);
        using var sha256 = SHA256.Create();
        return await sha256.ComputeHashAsync(stream, token).ConfigureAwait(false);
    }
}
