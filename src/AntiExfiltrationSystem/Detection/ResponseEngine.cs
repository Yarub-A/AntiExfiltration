using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using AntiExfiltrationSystem.Utilities;

namespace AntiExfiltrationSystem.Detection;

public sealed class ResponseEngine
{
    public string Enforce(PayloadAnalysisResult result, byte[] payload)
    {
        var severity = AssessThreatLevel(result);
        return severity switch
        {
            ThreatLevel.Low => "Log",
            ThreatLevel.Medium => ApplyMediumResponse(result, payload),
            ThreatLevel.High => ApplyHighResponse(result, payload),
            ThreatLevel.Critical => ApplyCriticalResponse(result, payload),
            _ => "Log"
        };
    }

    private static ThreatLevel AssessThreatLevel(PayloadAnalysisResult result)
    {
        var score = result.Indicators.Count * 0.2;
        if (result.Entropy > 7.5)
        {
            score += 0.4;
        }

        if (!result.Context.Signature.IsTrusted)
        {
            score += 0.3;
        }

        return score switch
        {
            >= 1.0 => ThreatLevel.Critical,
            >= 0.7 => ThreatLevel.High,
            >= 0.4 => ThreatLevel.Medium,
            _ => ThreatLevel.Low
        };
    }

    private static string ApplyMediumResponse(PayloadAnalysisResult result, byte[] payload)
    {
        MaskSensitiveContent(payload);
        return "Obfuscate payload";
    }

    private static string ApplyHighResponse(PayloadAnalysisResult result, byte[] payload)
    {
        MaskSensitiveContent(payload);
        TerminateConnection(result.Context.RootProcess);
        return "Block connection";
    }

    private static string ApplyCriticalResponse(PayloadAnalysisResult result, byte[] payload)
    {
        MaskSensitiveContent(payload);
        TerminateConnection(result.Context.RootProcess);
        TryKillProcess(result.Context.RootProcess);
        return "Terminate process";
    }

    private static void MaskSensitiveContent(Span<byte> payload)
    {
        payload.Clear();
    }

    private static void TerminateConnection(Process process)
    {
        foreach (var connection in TcpIpHelper.GetActiveConnections().Where(c => c.ProcessId == process.Id))
        {
            TcpReset(connection.LocalEndPoint, connection.RemoteEndPoint);
        }
    }

    private static void TryKillProcess(Process process)
    {
        try
        {
            process.Kill(true);
        }
        catch
        {
        }
    }

    private static void TcpReset(IPEndPoint local, IPEndPoint remote)
    {
        var row = new MIB_TCPROW
        {
            dwState = 12,
            dwLocalAddr = BitConverter.ToUInt32(local.Address.GetAddressBytes(), 0),
            dwLocalPort = (uint)IPAddress.HostToNetworkOrder((short)local.Port),
            dwRemoteAddr = BitConverter.ToUInt32(remote.Address.GetAddressBytes(), 0),
            dwRemotePort = (uint)IPAddress.HostToNetworkOrder((short)remote.Port)
        };

        SetTcpEntry(ref row);
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetTcpEntry(ref MIB_TCPROW pTcpRow);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }
}

public enum ThreatLevel
{
    Low,
    Medium,
    High,
    Critical
}
