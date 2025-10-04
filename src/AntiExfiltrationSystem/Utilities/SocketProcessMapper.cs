using System.Net;
using System.Runtime.Versioning;

namespace AntiExfiltrationSystem.Utilities;

[SupportedOSPlatform("windows")]
public static class SocketProcessMapper
{
    public static int ResolveProcessId(IPEndPoint local, IPEndPoint remote)
    {
        var tcpRows = TcpIpHelper.GetActiveConnections();
        foreach (var row in tcpRows)
        {
            if (row.LocalEndPoint.Equals(local) && row.RemoteEndPoint.Equals(remote))
            {
                return row.ProcessId;
            }

            if (row.LocalEndPoint.Equals(local) && row.RemoteEndPoint.Address.Equals(IPAddress.Any))
            {
                return row.ProcessId;
            }
        }

        return 0;
    }
}
