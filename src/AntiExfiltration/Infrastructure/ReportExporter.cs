using AntiExfiltration.UI;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AntiExfiltration.Infrastructure;

public static class ReportExporter
{
    public static async Task<string> ExportAsync(string reportsDirectory, UiContext context, CancellationToken token)
    {
        Directory.CreateDirectory(reportsDirectory);
        var archivePath = Path.Combine(reportsDirectory, $"report-{DateTime.UtcNow:yyyyMMdd-HHmmss}.zip");

        using var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create);
        await WriteJsonEntryAsync(archive, "processes.json", context.ProcessMonitor.SnapshotProcesses(), token).ConfigureAwait(false);
        await WriteJsonEntryAsync(archive, "processTree.json", context.ProcessMonitor.BuildProcessTree(), token).ConfigureAwait(false);
        await WriteJsonEntryAsync(archive, "connections.json", context.NetworkInterceptor.SnapshotConnections(), token).ConfigureAwait(false);
        await WriteJsonEntryAsync(archive, "hooks.json", context.ApiHookManager.HookedProcesses.Values.ToList(), token).ConfigureAwait(false);
        await WriteJsonEntryAsync(archive, "loadHistory.json", context.LoadMonitor.SnapshotHistory(), token).ConfigureAwait(false);

        if (Directory.Exists(context.LogDirectory))
        {
            var latest = Directory.EnumerateFiles(context.LogDirectory, "log-*.bin", SearchOption.TopDirectoryOnly)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();
            if (latest is not null)
            {
                archive.CreateEntryFromFile(latest, Path.GetFileName(latest));
            }

            var keyPath = Path.Combine(context.LogDirectory, "log.key");
            if (File.Exists(keyPath))
            {
                archive.CreateEntryFromFile(keyPath, "log.key");
            }
        }

        return archivePath;
    }

    private static async Task WriteJsonEntryAsync<T>(ZipArchive archive, string entryName, T payload, CancellationToken token)
    {
        var entry = archive.CreateEntry(entryName, CompressionLevel.Optimal);
        await using var entryStream = entry.Open();
        await using var writer = new Utf8JsonWriter(entryStream, new JsonWriterOptions { Indented = true });
        JsonSerializer.Serialize(writer, payload, new JsonSerializerOptions { WriteIndented = true });
        await writer.FlushAsync(token).ConfigureAwait(false);
    }
}
