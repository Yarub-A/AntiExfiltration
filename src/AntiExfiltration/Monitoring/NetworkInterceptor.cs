using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using System.Collections.Generic;
using System.Diagnostics;
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

    public void SwitchInterface(string name)
    {
        _activeInterface = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    public async Task RunAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            var entries = TcpTableReader.GetAllTcpConnections();
            foreach (var entry in entries)
            {
                if (_actionManager.IsNetworkBlocked(entry.ProcessId))
                {
                    continue;
                }

                var analysis = _packetAnalyzer.Analyze(entry);
                if (analysis.Indicators.Count == 0)
                {
                    continue;
                }

                var score = _behaviorEngine.UpdateScore(entry.ProcessId, existing =>
                {
                    var updated = existing;
                    foreach (var indicator in analysis.Indicators)
                    {
                        updated = updated.WithIndicator(indicator.Description, indicator.ScoreImpact, _behaviorEngine.Configuration);
                    }

                    return updated;
                });

                _actionManager.EvaluateAndRespond(entry.ProcessId);

                if (analysis.ShouldBlock)
                {
                    _actionManager.BlockNetwork(entry.ProcessId);
                }

                _logger.Log(new
                {
                    timestamp = DateTimeOffset.UtcNow,
                    eventType = "networkIndicators",
                    entry.ProcessId,
                    entry.LocalAddress,
                    entry.RemoteAddress,
                    entry.RemotePort,
                    indicators = analysis.Indicators.Select(i => new { i.Description, i.ScoreImpact }),
                    score.Total,
                    score.Level
                });
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

        if (entry.RemotePort == 443 && IPAddress.TryParse(entry.RemoteAddress, out var address) && address.GetAddressBytes()[0] >= 200)
        {
            indicators.Add(new PacketIndicator("unrecognized443", 3));
        }

        if (_configuration.HighRiskHosts.Any(host => entry.RemoteAddress.Contains(host, StringComparison.OrdinalIgnoreCase)))
        {
            indicators.Add(new PacketIndicator("highRiskHost", 3));
        }

        foreach (var keyword in CredentialKeywords)
        {
            if (entry.PayloadSnapshot.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add(new PacketIndicator("exfilKeyword:" + keyword.Trim('='), 4));
            }
        }

        var shouldBlock = indicators.Any(i => i.ScoreImpact >= 4);
        return new PacketAnalysisResult(indicators, shouldBlock);
    }
}

internal sealed record PacketAnalysisResult(IReadOnlyList<PacketIndicator> Indicators, bool ShouldBlock);

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

public sealed class TcpRow
{
    private TcpRow(int processId, string localAddress, int localPort, string remoteAddress, int remotePort)
    {
        ProcessId = processId;
        LocalAddress = localAddress;
        LocalPort = localPort;
        RemoteAddress = remoteAddress;
        RemotePort = remotePort;
        PayloadSnapshot = string.Empty;
    }

    public int ProcessId { get; }
    public string LocalAddress { get; }
    public int LocalPort { get; }
    public string RemoteAddress { get; }
    public int RemotePort { get; }
    public string PayloadSnapshot { get; init; }

    internal static TcpRow FromNative(TcpTableReader.NativeMethods.MIB_TCPROW_OWNER_PID row)
    {
        var processId = (int)row.dwOwningPid;
        var localAddress = new IPAddress(row.dwLocalAddr).ToString();
        var localPort = (row.dwLocalPort[0] << 8) + row.dwLocalPort[1];
        var remoteAddress = new IPAddress(row.dwRemoteAddr).ToString();
        var remotePort = (row.dwRemotePort[0] << 8) + row.dwRemotePort[1];
        return new TcpRow(processId, localAddress, localPort, remoteAddress, remotePort);
    }
}
