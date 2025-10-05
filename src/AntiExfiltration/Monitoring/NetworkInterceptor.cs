using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace AntiExfiltration.Monitoring;

[SupportedOSPlatform("windows")]
public sealed class NetworkInterceptor
{
    private readonly SecureLogger _logger;
    private readonly BehaviorEngine _behaviorEngine;
    private readonly ActionManager _actionManager;
    private readonly NetworkConfiguration _configuration;
    private readonly PacketAnalyzer _packetAnalyzer;
    private readonly ConcurrentDictionary<string, TcpRow> _connections = new(StringComparer.OrdinalIgnoreCase);
    private NetworkInterface? _activeInterface;

    public NetworkInterceptor(
        SecureLogger logger,
        BehaviorEngine behaviorEngine,
        ActionManager actionManager,
        NetworkConfiguration configuration)
    {
        _logger = logger;
        _behaviorEngine = behaviorEngine;
        _actionManager = actionManager;
        _configuration = configuration;
        _packetAnalyzer = new PacketAnalyzer(configuration);
        AutoSelectInterface();
    }

    public NetworkInterface? ActiveInterface => _activeInterface;

    public bool SwitchInterface(string name)
    {
        var target = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

        if (target is null)
        {
            return false;
        }

        _activeInterface = target;
        _logger.Log(new
        {
            timestamp = DateTimeOffset.UtcNow,
            eventType = "interfaceSwitched",
            interfaceName = target.Name,
            target.NetworkInterfaceType,
            target.OperationalStatus
        });

        return true;
    }

    public async Task RunAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            var entries = TcpTableReader.GetAllTcpConnections();
            var observedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in entries)
            {
                if (_actionManager.IsNetworkBlocked(entry.ProcessId))
                {
                    continue;
                }

                var refreshed = entry with { LastObserved = DateTimeOffset.UtcNow };
                var key = BuildConnectionKey(refreshed);
                observedKeys.Add(key);

                var analysis = _packetAnalyzer.Analyze(refreshed);
                if (!string.IsNullOrEmpty(analysis.PayloadPreview))
                {
                    refreshed = refreshed with { PayloadSnapshot = analysis.PayloadPreview };
                }
                else if (_connections.TryGetValue(key, out var existing) && !string.IsNullOrEmpty(existing.PayloadSnapshot))
                {
                    refreshed = refreshed with { PayloadSnapshot = existing.PayloadSnapshot };
                }

                _connections[key] = refreshed;
                if (analysis.Indicators.Count == 0)
                {
                    continue;
                }

                if (refreshed.ProcessId <= 4)
                {
                    continue;
                }

                var score = _behaviorEngine.UpdateScore(refreshed.ProcessId, existing =>
                {
                    var updated = existing;
                    foreach (var indicator in analysis.Indicators)
                    {
                        updated = updated.WithIndicator(indicator.Description, indicator.ScoreImpact, _behaviorEngine.Configuration);
                    }

                    return updated;
                });

                _actionManager.EvaluateAndRespond(refreshed.ProcessId);

                if (analysis.ShouldBlock)
                {
                    _actionManager.BlockNetwork(refreshed.ProcessId);
                }

                _logger.Log(new
                {
                    timestamp = DateTimeOffset.UtcNow,
                    eventType = "networkIndicators",
                    refreshed.ProcessId,
                    refreshed.LocalAddress,
                    refreshed.RemoteAddress,
                    refreshed.RemotePort,
                    indicators = analysis.Indicators.Select(i => new { i.Description, i.ScoreImpact }),
                    analysis.PayloadPreview,
                    score.Total,
                    score.Level
                });
            }

            foreach (var key in _connections.Keys.ToArray())
            {
                if (!observedKeys.Contains(key))
                {
                    _connections.TryRemove(key, out _);
                }
            }

            await Task.Delay(_configuration.ScanInterval, token).ConfigureAwait(false);
        }
    }

    private void AutoSelectInterface()
    {
        _activeInterface = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .OrderByDescending(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? 1 : 0)
            .ThenBy(n => n.Name.StartsWith(_configuration.PrimaryInterfacePreference, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .FirstOrDefault();
    }

    public IReadOnlyList<TcpRow> SnapshotConnections()
        => _connections.Values
            .OrderByDescending(c => c.LastObserved)
            .Take(25)
            .ToList();

    private static string BuildConnectionKey(TcpRow row)
        => $"{row.ProcessId}:{row.LocalAddress}:{row.LocalPort}:{row.RemoteAddress}:{row.RemotePort}";
}

internal sealed class PacketAnalyzer
{
    private static readonly string[] CredentialKeywords =
    {
        "uid=",
        "cid=",
        "hwid=",
        "ver=4.0"
    };

    private readonly NetworkConfiguration _configuration;

    public PacketAnalyzer(NetworkConfiguration configuration)
    {
        _configuration = configuration;
    }

    public PacketAnalysisResult Analyze(TcpRow entry)
    {
        var indicators = new List<PacketIndicator>();
        var highlights = new List<string>();

        if (_configuration.SuspiciousPorts?.Contains(entry.RemotePort) == true)
        {
            indicators.Add(new PacketIndicator($"remotePort:{entry.RemotePort}", 3));
            highlights.Add($"Remote port {entry.RemotePort} is monitored");
        }

        if (_configuration.HighRiskHosts.Any(host => entry.RemoteAddress.Contains(host, StringComparison.OrdinalIgnoreCase)))
        {
            indicators.Add(new PacketIndicator("highRiskHost", 3));
            highlights.Add($"Destination matches high-risk host list");
        }

        foreach (var keyword in CredentialKeywords)
        {
            if (entry.PayloadSnapshot.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add(new PacketIndicator("exfilKeyword:" + keyword.Trim('='), 4));
                highlights.Add($"Payload contains '{keyword}'");
            }
        }

        var shouldBlock = indicators.Any(i => i.ScoreImpact >= 4);
        var preview = highlights.Count > 0
            ? string.Join("; ", highlights)
            : $"Connection to {entry.RemoteAddress}:{entry.RemotePort}";

        return new PacketAnalysisResult(indicators, shouldBlock, preview);
    }
}

internal sealed record PacketAnalysisResult(IReadOnlyList<PacketIndicator> Indicators, bool ShouldBlock, string PayloadPreview);

internal sealed record PacketIndicator(string Description, int ScoreImpact);

internal sealed class TcpTableReader
{
    public static IReadOnlyList<TcpRow> GetAllTcpConnections()
    {
        var buffer = IntPtr.Zero;
        var bufferLength = 0u;
        try
        {
            var result = NativeMethods.GetExtendedTcpTable(buffer, ref bufferLength, true, (int)AddressFamily.InterNetwork, NativeMethods.TcpTableType.OwnerPidConnections, 0);
            if (result != 0 && result != 122) // ERROR_INSUFFICIENT_BUFFER
            {
                return Array.Empty<TcpRow>();
            }

            buffer = Marshal.AllocHGlobal((int)bufferLength);
            result = NativeMethods.GetExtendedTcpTable(buffer, ref bufferLength, true, (int)AddressFamily.InterNetwork, NativeMethods.TcpTableType.OwnerPidConnections, 0);
            if (result != 0)
            {
                return Array.Empty<TcpRow>();
            }

            var table = Marshal.PtrToStructure<NativeMethods.MIB_TCPTABLE_OWNER_PID>(buffer);
            var rows = new List<TcpRow>((int)table.dwNumEntries);
            var rowPtr = (IntPtr)((long)buffer + Marshal.SizeOf(table.dwNumEntries));
            for (var i = 0; i < table.dwNumEntries; i++)
            {
            var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(rowPtr);
            rows.Add(TcpRow.FromNative(row));
            rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>());
        }

        return rows;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    internal static class NativeMethods
    {
        public enum TcpTableType
        {
            BasicListener,
            BasicConnections,
            BasicAll,
            OwnerPidListener,
            OwnerPidConnections,
            OwnerPidAll,
            OwnerModuleListener,
            OwnerModuleConnections,
            OwnerModuleAll
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            private readonly MIB_TCPROW_OWNER_PID table;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] dwLocalPort;
            public uint dwRemoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] dwRemotePort;
            public uint dwOwningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref uint dwOutBufLen, bool sort, int ipVersion, TcpTableType tblClass, int reserved);
    }
}

public sealed record TcpRow(int ProcessId, string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort)
{
    public DateTimeOffset LastObserved { get; init; } = DateTimeOffset.UtcNow;
    public string PayloadSnapshot { get; init; } = string.Empty;

    internal static TcpRow FromNative(TcpTableReader.NativeMethods.MIB_TCPROW_OWNER_PID row)
    {
        var processId = (int)row.dwOwningPid;
        var localAddress = new IPAddress(row.dwLocalAddr).ToString();
        var localPort = (row.dwLocalPort[0] << 8) + row.dwLocalPort[1];
        var remoteAddress = new IPAddress(row.dwRemoteAddr).ToString();
        var remotePort = (row.dwRemotePort[0] << 8) + row.dwRemotePort[1];
        return new TcpRow(processId, localAddress, localPort, remoteAddress, remotePort)
        {
            LastObserved = DateTimeOffset.UtcNow
        };
    }
}
