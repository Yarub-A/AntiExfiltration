using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace AntiExfiltrationSystem.Utilities;

[SupportedOSPlatform("windows")]
public static class TcpIpHelper
{
    private const int AF_INET = 2;

    public static int ResolveOwningProcess(IPEndPoint remote)
    {
        var tcpRows = GetTcpTable();
        foreach (var row in tcpRows)
        {
            if (row.RemoteEndPoint.Equals(remote))
            {
                return row.ProcessId;
            }
        }

        return 0;
    }

    public static IReadOnlyList<TcpConnectionInfo> GetActiveConnections() => GetTcpTable();

    public static string DetectProtocol(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20)
        {
            return "UNKNOWN";
        }

        return packet[9] switch
        {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "OTHER"
        };
    }

    private static IReadOnlyList<TcpConnectionInfo> GetTcpTable()
    {
        var bufferSize = 0;
        var result = IpHlpApi.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0);
        if (result != 0 && result != 122)
        {
            throw new InvalidOperationException($"GetExtendedTcpTable failed: {result}");
        }

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            result = IpHlpApi.GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0);
            if (result != 0)
            {
                throw new InvalidOperationException($"GetExtendedTcpTable failed: {result}");
            }

            var table = Marshal.PtrToStructure<MibTcpTableOwnerPid>(buffer);
            var capacity = table.NumEntries >= int.MaxValue ? int.MaxValue : (int)table.NumEntries;
            var rows = new List<TcpConnectionInfo>(capacity);
            var rowPtr = buffer + Marshal.SizeOf<MibTcpTableOwnerPid>();
            for (var i = 0; i < table.NumEntries; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                rows.Add(new TcpConnectionInfo(
                    row.State,
                    new IPEndPoint(row.LocalAddress, ConvertPort(row.LocalPort)),
                    new IPEndPoint(row.RemoteAddress, ConvertPort(row.RemotePort)),
                    (int)row.OwningPid));
                rowPtr += Marshal.SizeOf<MibTcpRowOwnerPid>();
            }

            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ConvertPort(uint port)
    {
        var be = BinaryPrimitives.ReverseEndianness((ushort)port);
        return be;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct MibTcpTableOwnerPid
    {
        public readonly uint NumEntries;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct MibTcpRowOwnerPid
    {
        public readonly uint State;
        public readonly MibIpAddress LocalAddr;
        public readonly uint LocalPort;
        public readonly MibIpAddress RemoteAddr;
        public readonly uint RemotePort;
        public readonly uint OwningPid;

        public IPAddress LocalAddress => new(LocalAddr.Address);
        public IPAddress RemoteAddress => new(RemoteAddr.Address);
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct MibIpAddress
    {
        public readonly uint Address;
        public readonly uint ScopeId;
    }
}

public readonly record struct TcpConnectionInfo(
    uint State,
    IPEndPoint LocalEndPoint,
    IPEndPoint RemoteEndPoint,
    int ProcessId);

[SupportedOSPlatform("windows")]
internal static class IpHlpApi
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern int GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TcpTableClass tblClass,
        uint reserved = 0);
}

internal enum TcpTableClass
{
    TCP_TABLE_BASIC_LISTENER,
    TCP_TABLE_BASIC_CONNECTIONS,
    TCP_TABLE_BASIC_ALL,
    TCP_TABLE_OWNER_PID_LISTENER,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
    TCP_TABLE_OWNER_PID_ALL,
    TCP_TABLE_OWNER_MODULE_LISTENER,
    TCP_TABLE_OWNER_MODULE_CONNECTIONS,
    TCP_TABLE_OWNER_MODULE_ALL
}
