using System.Net.NetworkInformation;

namespace AntiExfiltrationSystem.Networking;

public static class NetworkAdapterManager
{
    public static IReadOnlyList<NetworkInterface> DetectAdapters()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.NetworkInterfaceType != NetworkInterfaceType.Loopback && nic.OperationalStatus == OperationalStatus.Up)
            .Where(nic => nic.GetIPProperties().UnicastAddresses.Any(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))
            .ToList();
    }
}
