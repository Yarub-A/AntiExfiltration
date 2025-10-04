using System.Collections.Concurrent;
using System.Net;

namespace AntiExfiltrationSystem.Utilities;

public static class PacketRepository
{
    private static readonly ConcurrentDictionary<int, ConcurrentQueue<PacketRecord>> Storage = new();
    private const int MaxPacketsPerProcess = 128;

    public static void AddPacket(int processId, byte[] payload, IPEndPoint endpoint)
    {
        var queue = Storage.GetOrAdd(processId, _ => new ConcurrentQueue<PacketRecord>());
        queue.Enqueue(new PacketRecord(payload, endpoint, DateTime.UtcNow));
        while (queue.Count > MaxPacketsPerProcess && queue.TryDequeue(out _))
        {
        }
    }

    public static IReadOnlyList<PacketRecord> GetPacketsByProcess(int processId)
    {
        if (Storage.TryGetValue(processId, out var queue))
        {
            return queue.ToArray();
        }

        return Array.Empty<PacketRecord>();
    }
}

public readonly record struct PacketRecord(byte[] Payload, IPEndPoint RemoteEndpoint, DateTime Timestamp);
