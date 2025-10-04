using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AntiExfiltrationSystem.Utilities;

namespace AntiExfiltrationSystem.ProcessMonitoring;

public sealed class ProcessTracker
{
    public ProcessContext GetProcessContext(int processId)
    {
        var process = Process.GetProcessById(processId);
        var parentChain = BuildParentChain(process);
        var children = BuildChildProcesses(processId);
        var connections = CollectNetworkConnections(processId);
        var signature = EvaluateSignature(process);

        return new ProcessContext
        {
            RootProcess = process,
            ParentChain = parentChain,
            ChildProcesses = children,
            NetworkConnections = connections,
            Signature = signature
        };
    }

    private static IReadOnlyList<Process> BuildParentChain(Process process)
    {
        var chain = new List<Process>();
        try
        {
            var parentId = ProcessExtensions.GetParentProcessId(process);
            while (parentId > 0)
            {
                try
                {
                    var parent = Process.GetProcessById(parentId);
                    chain.Add(parent);
                    parentId = ProcessExtensions.GetParentProcessId(parent);
                }
                catch (ArgumentException)
                {
                    break;
                }
            }
        }
        catch (Win32Exception)
        {
        }

        return chain;
    }

    private static IReadOnlyList<Process> BuildChildProcesses(int processId)
    {
        var children = new List<Process>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (ProcessExtensions.GetParentProcessId(process) == processId)
                {
                    children.Add(process);
                }
            }
            catch (Win32Exception)
            {
            }
        }

        return children;
    }

    private static IReadOnlyList<NetworkConnection> CollectNetworkConnections(int processId)
    {
        var connections = new List<NetworkConnection>();
        var packets = PacketRepository.GetPacketsByProcess(processId);
        foreach (var connection in TcpIpHelper.GetActiveConnections().Where(c => c.ProcessId == processId))
        {
            var bytesTransferred = packets
                .Where(p => p.RemoteEndpoint.Equals(connection.RemoteEndPoint))
                .Sum(p => (long)p.Payload.Length);
            connections.Add(new NetworkConnection
            {
                LocalEndpoint = connection.LocalEndPoint,
                RemoteEndpoint = connection.RemoteEndPoint,
                Protocol = "TCP",
                State = ((TcpState)connection.State).ToString(),
                BytesTransferred = bytesTransferred,
                EstablishedAt = DateTime.UtcNow
            });
        }

        return connections;
    }

    private static SignatureStatus EvaluateSignature(Process process)
    {
        try
        {
            var path = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(path))
            {
                return new SignatureStatus { IsSigned = false, IsTrusted = false, Subject = "Unknown" };
            }

            // تحميل شهادة التوقيع من الملف التنفيذي بطريقة متوافقة مع كافة الإصدارات
            var certificate = X509Certificate.CreateFromSignedFile(path);
            var signer = new X509Certificate2(certificate);

            var chain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    VerificationFlags = X509VerificationFlags.IgnoreInvalidName
                }
            };
            var trusted = chain.Build(signer);

            return new SignatureStatus
            {
                IsSigned = true,
                IsTrusted = trusted,
                Subject = signer.Subject
            };
        }
        catch (CryptographicException)
        {
            return new SignatureStatus { IsSigned = false, IsTrusted = false, Subject = "Unsigned" };
        }
        catch (Win32Exception)
        {
            return new SignatureStatus { IsSigned = false, IsTrusted = false, Subject = "Unavailable" };
        }
    }
}

internal static class ProcessExtensions
{
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

    public static int GetParentProcessId(Process process)
    {
        var pbi = new PROCESS_BASIC_INFORMATION();
        var status = NtQueryInformationProcess(process.Handle, 0, ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
        if (status != 0)
        {
            return 0;
        }

        return pbi.InheritedFromUniqueProcessId.ToInt32();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }
}

internal enum TcpState
{
    Closed = 1,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb
}
