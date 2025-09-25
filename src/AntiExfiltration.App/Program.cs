using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AntiExfiltration.Core.Action;
using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Common;
using AntiExfiltration.Core.Context;
using AntiExfiltration.Core.Decisions;
using AntiExfiltration.Core.Intel;
using AntiExfiltration.Core.Logging;
using AntiExfiltration.Core.Policy;
using AntiExfiltration.Core.Pipeline;
using PacketDotNet;
using SharpPcap;

Console.OutputEncoding = Encoding.UTF8;
var settings = AppSettings.Parse(args);
var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cts.Cancel();
};

Console.WriteLine("🛡️ Anti-Exfiltration Console");
Console.WriteLine("============================\n");
Console.WriteLine(settings.Mode switch
{
    RunMode.Live => "الوضع: التقاط مباشر من بطاقة الشبكة.",
    RunMode.Demo => "الوضع: سيناريوهات تدريبية داخلية.",
    _ => string.Empty
});
Console.WriteLine();

var threatIntel = new ThreatIntelManager();
threatIntel.LoadDestinations(new[] { "203.0.113.50", "198.51.100.22" });
threatIntel.LoadKeywords(new[] { "password", "secret", "token", "exfil" });

var processResolver = settings.Mode == RunMode.Live
    ? (IProcessContextResolver)new SystemProcessContextResolver()
    : new DemoProcessContextResolver();

ICaptureProvider captureProvider = settings.Mode == RunMode.Live
    ? new PcapCaptureProvider(settings.DeviceName, settings.BpfFilter, new ProcessPortMapper())
    : new DemoCaptureProvider(settings.DemoInterval);

var analyzers = new IAnalyzer[]
{
    new SignatureAnalyzer(threatIntel),
    new EntropyAnalyzer()
};

var policyEngine = new PolicyEngine(analyzers, processResolver);
var decisionEngine = new DecisionEngine(new DecisionEngineOptions());
var logFilePath = Path.Combine(AppContext.BaseDirectory, "events.log");
IEventLogger logger = new CompositeEventLogger(new IEventLogger[]
{
    new ConsoleEventLogger(),
    new JsonEventLogger(logFilePath)
});

var packetDropper = new ConsolePacketDropper();
var dataObfuscator = new PayloadDataObfuscator();
var processTerminator = new SafeProcessTerminator(settings.AllowProcessTermination);
IEnforcementAction actionExecutor = new ActionExecutor(packetDropper, dataObfuscator, processTerminator, logger);

var pipeline = new AntiExfiltrationPipeline(captureProvider, policyEngine, decisionEngine, actionExecutor);
pipeline.Start();

Console.WriteLine("✅ النظام بدأ العمل. اضغط Ctrl+C للإيقاف.");
Console.WriteLine(settings.Mode == RunMode.Live
    ? "لإختيار واجهة أخرى استخدم --device أو اعرض الأجهزة بواسطة SharpPcap (tshark -D)."
    : $"يتم توليد الحزم التدريبية كل {settings.DemoInterval.TotalSeconds} ثانية.");
Console.WriteLine($"سجلات JSON تكتب في: {logFilePath}\n");

try
{
    await Task.Delay(Timeout.InfiniteTimeSpan, cts.Token);
}
catch (TaskCanceledException)
{
    // Expected on Ctrl+C.
}
finally
{
    if (captureProvider is IDisposable disposable)
    {
        disposable.Dispose();
    }
}

Console.WriteLine("🛑 تم إنهاء النظام.");

file enum RunMode
{
    Live,
    Demo
}

file sealed record AppSettings(
    RunMode Mode,
    string? DeviceName,
    string? BpfFilter,
    TimeSpan DemoInterval,
    bool AllowProcessTermination)
{
    public static AppSettings Parse(string[] arguments)
    {
        var mode = RunMode.Demo;
        string? device = null;
        string? filter = null;
        var interval = TimeSpan.FromSeconds(5);
        var allowKill = false;

        for (var i = 0; i < arguments.Length; i++)
        {
            switch (arguments[i])
            {
                case "--mode":
                    if (i + 1 >= arguments.Length)
                    {
                        throw new ArgumentException("يجب تحديد قيمة بعد --mode (demo أو live).");
                    }

                    var value = arguments[++i];
                    mode = value.Equals("live", StringComparison.OrdinalIgnoreCase) ? RunMode.Live : RunMode.Demo;
                    break;
                case "--device":
                    if (i + 1 >= arguments.Length)
                    {
                        throw new ArgumentException("يجب تحديد اسم واجهة بعد --device.");
                    }

                    device = arguments[++i];
                    break;
                case "--filter":
                    if (i + 1 >= arguments.Length)
                    {
                        throw new ArgumentException("يجب تحديد قيمة بعد --filter.");
                    }

                    filter = arguments[++i];
                    break;
                case "--interval":
                    if (i + 1 >= arguments.Length || !int.TryParse(arguments[++i], out var seconds) || seconds <= 0)
                    {
                        throw new ArgumentException("قيمة --interval يجب أن تكون عدد ثوانٍ أكبر من الصفر.");
                    }

                    interval = TimeSpan.FromSeconds(seconds);
                    break;
                case "--allow-kill":
                    allowKill = true;
                    break;
                case "--help":
                case "-h":
                    PrintHelp();
                    Environment.Exit(0);
                    break;
                default:
                    Console.WriteLine($"وسيط غير معروف: {arguments[i]}");
                    PrintHelp();
                    Environment.Exit(1);
                    break;
            }
        }

        return new AppSettings(mode, device, filter, interval, allowKill);
    }

    private static void PrintHelp()
    {
        Console.WriteLine("استخدام التطبيق:");
        Console.WriteLine("  dotnet run --project src/AntiExfiltration.App [خيارات]\n");
        Console.WriteLine("الخيارات:");
        Console.WriteLine("  --mode [demo|live]      اختيار نمط العمل (افتراضي demo).");
        Console.WriteLine("  --device <name>         واجهة الشبكة المستهدفة في وضع live.");
        Console.WriteLine("  --filter <bpf>          مرشح BPF لتقليص الحزم الملتقطة.");
        Console.WriteLine("  --interval <seconds>    تردد توليد الحزم في وضع demo (افتراضي 5).");
        Console.WriteLine("  --allow-kill            السماح بمحاولة إنهاء العملية المخالفة (خطر في وضع live).");
        Console.WriteLine("  --help                  عرض هذه الرسالة.");
    }
}

file sealed class CompositeEventLogger : IEventLogger
{
    private readonly IReadOnlyList<IEventLogger> _loggers;

    public CompositeEventLogger(IReadOnlyList<IEventLogger> loggers)
    {
        _loggers = loggers;
    }

    public void LogAllow(RawPacket packet, ProcessInfo processInfo) => Broadcast(logger => logger.LogAllow(packet, processInfo));
    public void LogBlock(RawPacket packet, ProcessInfo processInfo) => Broadcast(logger => logger.LogBlock(packet, processInfo));
    public void LogObfuscation(RawPacket packet, ProcessInfo processInfo) => Broadcast(logger => logger.LogObfuscation(packet, processInfo));
    public void LogAlert(RawPacket packet, ProcessInfo processInfo) => Broadcast(logger => logger.LogAlert(packet, processInfo));

    private void Broadcast(Action<IEventLogger> action)
    {
        foreach (var logger in _loggers)
        {
            action(logger);
        }
    }
}

file sealed class ConsoleEventLogger : IEventLogger
{
    private readonly object _sync = new();

    public void LogAllow(RawPacket packet, ProcessInfo processInfo)
        => WriteLine("ALLOW", ConsoleColor.DarkGray, packet, processInfo, "حركة طبيعية");

    public void LogBlock(RawPacket packet, ProcessInfo processInfo)
        => WriteLine("BLOCK", ConsoleColor.Red, packet, processInfo, "تم الحجب");

    public void LogObfuscation(RawPacket packet, ProcessInfo processInfo)
        => WriteLine("OBFUSCATE", ConsoleColor.Yellow, packet, processInfo, "تشويش الحمولة");

    public void LogAlert(RawPacket packet, ProcessInfo processInfo)
        => WriteLine("ALERT", ConsoleColor.Cyan, packet, processInfo, "تنبيه");

    private void WriteLine(string action, ConsoleColor color, RawPacket packet, ProcessInfo processInfo, string message)
    {
        lock (_sync)
        {
            var previous = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(
                $"[{DateTimeOffset.UtcNow:HH:mm:ss}] {action} | العملية: {processInfo.Name} (PID {processInfo.Pid}) -> {packet.Destination} | {message} | حجم {packet.Payload.Length} بايت");
            Console.ForegroundColor = previous;
        }
    }
}

file sealed class ConsolePacketDropper : IPacketDropper
{
    public void Drop(RawPacket packet)
    {
        Console.WriteLine($"[DROP] تم طلب حجب الاتصال نحو {packet.Destination}.");
    }
}

file sealed class PayloadDataObfuscator : IDataObfuscator
{
    public void Obfuscate(RawPacket packet)
    {
        if (packet.Payload.Length == 0)
        {
            return;
        }

        RandomNumberGenerator.Fill(packet.Payload);
        Console.WriteLine($"[OBFUSCATE] تم تشويش الحمولة ({packet.Payload.Length} بايت).");
    }
}

file sealed class SafeProcessTerminator : IProcessTerminator
{
    private readonly bool _allowTermination;

    public SafeProcessTerminator(bool allowTermination)
    {
        _allowTermination = allowTermination;
    }

    public void Terminate(ProcessInfo processInfo)
    {
        if (!_allowTermination)
        {
            Console.WriteLine($"[WARN] لم يتم إنهاء العملية {processInfo.Name} (PID {processInfo.Pid}) لأن الإعداد --allow-kill غير مُفعل.");
            return;
        }

        if (processInfo.Pid <= 0 || processInfo.IsSystemProcess)
        {
            Console.WriteLine($"[WARN] تجاهل إنهاء العملية PID {processInfo.Pid} حفاظًا على استقرار النظام.");
            return;
        }

        try
        {
            using var process = Process.GetProcessById(processInfo.Pid);
            process.Kill(true);
            Console.WriteLine($"[KILL] تم إنهاء العملية {processInfo.Name} (PID {processInfo.Pid}).");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] تعذر إنهاء العملية {processInfo.Pid}: {ex.Message}");
        }
    }
}

file sealed class DemoCaptureProvider : ICaptureProvider, IDisposable
{
    private readonly TimeSpan _interval;
    private readonly CancellationTokenSource _cts = new();
    private Task? _worker;
    private readonly Random _random = new();

    public DemoCaptureProvider(TimeSpan interval)
    {
        _interval = interval < TimeSpan.FromMilliseconds(500)
            ? TimeSpan.FromMilliseconds(500)
            : interval;
    }

    public event EventHandler<PacketCapturedEventArgs>? PacketCaptured;

    public void Start()
    {
        _worker = Task.Run(async () =>
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                await Task.Delay(_interval, _cts.Token).ConfigureAwait(false);
                EmitScenario();
            }
        }, _cts.Token);

        Console.WriteLine($"🧪 بدء الوضع التدريبي. سيتم توليد حزم كل {_interval.TotalSeconds} ثانية.");
    }

    private void EmitScenario()
    {
        var scenarios = DemoScenarioLibrary.Scenarios;
        var scenario = scenarios[_random.Next(scenarios.Length)];
        var payload = Encoding.UTF8.GetBytes(scenario.Payload);
        var packet = new RawPacket(
            payload,
            new IPEndPoint(IPAddress.Parse(scenario.SourceIp), scenario.SourcePort),
            new IPEndPoint(IPAddress.Parse(scenario.DestinationIp), scenario.DestinationPort),
            scenario.Protocol,
            scenario.ProcessId,
            DateTimeOffset.UtcNow);

        PacketCaptured?.Invoke(this, new PacketCapturedEventArgs(packet));
    }

    public void Dispose()
    {
        _cts.Cancel();
        try
        {
            _worker?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
            // Ignore.
        }
    }

    private static class DemoScenarioLibrary
    {
        public static readonly DemoScenario[] Scenarios =
        {
            new("10.0.0.5", 49152, "203.0.113.50", 443, ProtocolType.Https, 4242, "username=admin&password=P@ssw0rd"),
            new("10.0.0.12", 51515, "198.51.100.22", 80, ProtocolType.Http, 4243, "GET /export?token=leak HTTP/1.1"),
            new("10.0.0.30", 53000, "192.0.2.99", 53, ProtocolType.Dns, 4244, "leakedomain.example"),
            new("10.0.0.8", 55000, "203.0.113.77", 443, ProtocolType.Https, 5001, "harmless telemetry ping")
        };
    }

    private sealed record DemoScenario(
        string SourceIp,
        int SourcePort,
        string DestinationIp,
        int DestinationPort,
        ProtocolType Protocol,
        int ProcessId,
        string Payload);
}

file sealed class DemoProcessContextResolver : IProcessContextResolver
{
    private static readonly Dictionary<int, ProcessInfo> Processes = new()
    {
        [4242] = new ProcessInfo
        {
            Pid = 4242,
            Name = "VaultUploader.exe",
            ExecutablePath = "C:/Sandbox/VaultUploader.exe",
            DigitalSignature = "Unknown",
            ParentPid = 4000,
            IsSystemProcess = false
        },
        [4243] = new ProcessInfo
        {
            Pid = 4243,
            Name = "BrowserAutomation.exe",
            ExecutablePath = "C:/Sandbox/BrowserAutomation.exe",
            DigitalSignature = "Unsigned",
            ParentPid = 1000,
            IsSystemProcess = false
        },
        [4244] = new ProcessInfo
        {
            Pid = 4244,
            Name = "DnsBeacon.exe",
            ExecutablePath = "C:/Sandbox/DnsBeacon.exe",
            DigitalSignature = "Unsigned",
            ParentPid = 1000,
            IsSystemProcess = false
        },
        [5001] = new ProcessInfo
        {
            Pid = 5001,
            Name = "TelemetryService.exe",
            ExecutablePath = "C:/Program Files/Telemetry/Service.exe",
            DigitalSignature = "Contoso Inc.",
            ParentPid = 4,
            IsSystemProcess = false
        }
    };

    public ProcessInfo Resolve(int processId)
    {
        if (Processes.TryGetValue(processId, out var info))
        {
            return info;
        }

        return new ProcessInfo
        {
            Pid = processId,
            Name = "DemoProcess",
            ExecutablePath = "C:/Sandbox/DemoProcess.exe",
            DigitalSignature = "Unsigned",
            ParentPid = 0,
            IsSystemProcess = false
        };
    }
}

file sealed class SystemProcessContextResolver : IProcessContextResolver
{
    public ProcessInfo Resolve(int processId)
    {
        if (processId <= 0)
        {
            return Unknown(processId);
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            var path = TryGetMainModule(process) ?? "غير متوفر";
            var signature = TryGetDigitalSignature(path);
            var isSystem = IsSystemProcess(path);
            return new ProcessInfo
            {
                Pid = processId,
                Name = process.ProcessName,
                ExecutablePath = path,
                DigitalSignature = signature,
                ParentPid = 0,
                IsSystemProcess = isSystem
            };
        }
        catch (Exception ex)
        {
            return new ProcessInfo
            {
                Pid = processId,
                Name = "غير معروف",
                ExecutablePath = ex.Message,
                DigitalSignature = "غير متوفر",
                ParentPid = 0,
                IsSystemProcess = false
            };
        }
    }

    private static ProcessInfo Unknown(int pid) => new()
    {
        Pid = pid,
        Name = "غير معروف",
        ExecutablePath = "غير متوفر",
        DigitalSignature = "غير متوفر",
        ParentPid = 0,
        IsSystemProcess = false
    };

    private static string? TryGetMainModule(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static string TryGetDigitalSignature(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return "غير موقّع";
        }

        try
        {
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            return certificate.Subject;
        }
        catch
        {
            return "غير موقّع";
        }
    }

    private static bool IsSystemProcess(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        try
        {
            var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}

file sealed class PcapCaptureProvider : ICaptureProvider, IDisposable
{
    private readonly string? _deviceName;
    private readonly string? _bpfFilter;
    private readonly ProcessPortMapper _portMapper;
    private ICaptureDevice? _device;
    private bool _started;

    public PcapCaptureProvider(string? deviceName, string? bpfFilter, ProcessPortMapper portMapper)
    {
        _deviceName = deviceName;
        _bpfFilter = bpfFilter;
        _portMapper = portMapper;
    }

    public event EventHandler<PacketCapturedEventArgs>? PacketCaptured;

    public void Start()
    {
        var devices = CaptureDeviceList.Instance;
        if (devices.Count == 0)
        {
            throw new InvalidOperationException("لم يتم العثور على أي واجهة شبكة لالتقاط الحزم.");
        }

        _device = SelectDevice(devices, _deviceName);
        _device.OnPacketArrival += HandlePacketArrival;
        _device.Open(DeviceModes.Promiscuous, read_timeout: 1000);
        if (!string.IsNullOrWhiteSpace(_bpfFilter))
        {
            _device.Filter = _bpfFilter;
        }

        _device.StartCapture();
        _started = true;
        Console.WriteLine($"🟢 بدأ التقاط الحزم على الواجهة: {_device.Name}");
    }

    private void HandlePacketArrival(object sender, PacketCapture capture)
    {
        try
        {
            var rawCapture = capture.GetPacket();
            var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
            if (packet.Extract<IpPacket>() is not { } ipPacket)
            {
                return;
            }

            if (packet.Extract<TcpPacket>() is { } tcpPacket)
            {
                EmitPacket(ipPacket, tcpPacket, null);
            }
            else if (packet.Extract<UdpPacket>() is { } udpPacket)
            {
                EmitPacket(ipPacket, null, udpPacket);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[PCAP] خطأ أثناء معالجة الحزمة: {ex.Message}");
        }
    }

    private void EmitPacket(IpPacket ipPacket, TcpPacket? tcpPacket, UdpPacket? udpPacket)
    {
        byte[] payload;
        ProtocolType protocolType;
        IPEndPoint source;
        IPEndPoint destination;

        if (tcpPacket is not null)
        {
            payload = tcpPacket.PayloadData ?? Array.Empty<byte>();
            source = new IPEndPoint(ipPacket.SourceAddress, tcpPacket.SourcePort);
            destination = new IPEndPoint(ipPacket.DestinationAddress, tcpPacket.DestinationPort);
            protocolType = MapTcpProtocol(tcpPacket.DestinationPort);
        }
        else if (udpPacket is not null)
        {
            payload = udpPacket.PayloadData ?? Array.Empty<byte>();
            source = new IPEndPoint(ipPacket.SourceAddress, udpPacket.SourcePort);
            destination = new IPEndPoint(ipPacket.DestinationAddress, udpPacket.DestinationPort);
            protocolType = udpPacket.DestinationPort == 53 || udpPacket.SourcePort == 53
                ? ProtocolType.Dns
                : ProtocolType.Udp;
        }
        else
        {
            return;
        }

        var processId = _portMapper.ResolveProcessId(source, destination, protocolType);
        var packet = new RawPacket(
            payload,
            source,
            destination,
            protocolType,
            processId,
            DateTimeOffset.UtcNow);

        PacketCaptured?.Invoke(this, new PacketCapturedEventArgs(packet));
    }

    private static ProtocolType MapTcpProtocol(int destinationPort)
        => destinationPort switch
        {
            80 => ProtocolType.Http,
            443 => ProtocolType.Https,
            8080 => ProtocolType.Http,
            _ => ProtocolType.Tcp
        };

    private static ICaptureDevice SelectDevice(CaptureDeviceList devices, string? requested)
    {
        if (string.IsNullOrWhiteSpace(requested))
        {
            foreach (var device in devices)
            {
                if (!device.Name.Contains("Loopback", StringComparison.OrdinalIgnoreCase))
                {
                    return device;
                }
            }

            return devices[0];
        }

        foreach (var device in devices)
        {
            if (device.Name.Equals(requested, StringComparison.OrdinalIgnoreCase) ||
                device.Description.Contains(requested, StringComparison.OrdinalIgnoreCase))
            {
                return device;
            }
        }

        throw new InvalidOperationException($"الواجهة '{requested}' غير موجودة.");
    }

    public void Dispose()
    {
        if (_device is null)
        {
            return;
        }

        try
        {
            if (_started)
            {
                _device.StopCapture();
            }
        }
        catch
        {
            // Ignore stop errors.
        }
        finally
        {
            _device.OnPacketArrival -= HandlePacketArrival;
            _device.Close();
        }
    }
}

file sealed class ProcessPortMapper
{
    private readonly object _sync = new();
    private DateTime _lastRefresh = DateTime.MinValue;
    private IReadOnlyList<WindowsTcpRow> _tcpRows = Array.Empty<WindowsTcpRow>();
    private static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(3);

    public int ResolveProcessId(IPEndPoint source, IPEndPoint destination, ProtocolType protocol)
    {
        if (!OperatingSystem.IsWindows())
        {
            return -1;
        }

        if (protocol is ProtocolType.Tcp or ProtocolType.Http or ProtocolType.Https or ProtocolType.WebSocket)
        {
            var rows = GetTcpRows();
            foreach (var row in rows)
            {
                if (row.Matches(source, destination))
                {
                    return (int)row.OwningPid;
                }
            }
        }

        return -1;
    }

    private IReadOnlyList<WindowsTcpRow> GetTcpRows()
    {
        lock (_sync)
        {
            if (DateTime.UtcNow - _lastRefresh < CacheDuration)
            {
                return _tcpRows;
            }

            _tcpRows = WindowsTcpTable.GetTcpRows();
            _lastRefresh = DateTime.UtcNow;
            return _tcpRows;
        }
    }
}

file readonly struct WindowsTcpRow
{
    public WindowsTcpRow(IPAddress localAddress, int localPort, IPAddress remoteAddress, int remotePort, uint owningPid)
    {
        LocalAddress = localAddress;
        LocalPort = localPort;
        RemoteAddress = remoteAddress;
        RemotePort = remotePort;
        OwningPid = owningPid;
    }

    public IPAddress LocalAddress { get; }
    public int LocalPort { get; }
    public IPAddress RemoteAddress { get; }
    public int RemotePort { get; }
    public uint OwningPid { get; }

    public bool Matches(IPEndPoint source, IPEndPoint destination)
    {
        var remoteMatch = RemoteAddress.Equals(IPAddress.Any) || RemoteAddress.Equals(IPAddress.None) || RemoteAddress.Equals(destination.Address);
        var portsMatch = LocalPort == source.Port && (RemotePort == 0 || RemotePort == destination.Port);
        var addressMatch = LocalAddress.Equals(IPAddress.Any) || LocalAddress.Equals(source.Address);
        return portsMatch && addressMatch && remoteMatch;
    }
}

file static class WindowsTcpTable
{
    private const int AfInet = 2;
    private const uint ErrorInsufficientBuffer = 122;

    public static IReadOnlyList<WindowsTcpRow> GetTcpRows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<WindowsTcpRow>();
        }

        var buffer = IntPtr.Zero;
        try
        {
            int bufferLength = 0;
            var result = GetExtendedTcpTable(IntPtr.Zero, ref bufferLength, true, AfInet, TcpTableClass.OwnerPidAll, 0);
            if (result != ErrorInsufficientBuffer && result != 0)
            {
                throw new InvalidOperationException($"GetExtendedTcpTable فشل بالرمز {result}");
            }

            buffer = Marshal.AllocHGlobal(bufferLength);
            result = GetExtendedTcpTable(buffer, ref bufferLength, true, AfInet, TcpTableClass.OwnerPidAll, 0);
            if (result != 0)
            {
                throw new InvalidOperationException($"GetExtendedTcpTable فشل بالرمز {result}");
            }

            var managed = new byte[bufferLength];
            Marshal.Copy(buffer, managed, 0, bufferLength);

            var count = (int)MemoryMarshal.Read<uint>(managed);
            var rows = MemoryMarshal.Cast<byte, MibTcpRowOwnerPid>(managed.AsSpan(sizeof(uint))); // skip count
            var resultRows = new List<WindowsTcpRow>(count);
            for (var i = 0; i < Math.Min(count, rows.Length); i++)
            {
                var row = rows[i];
                var localAddress = new IPAddress(row.LocalAddr);
                var remoteAddress = new IPAddress(row.RemoteAddr);
                var localPort = BinaryPrimitives.ReverseEndianness((ushort)row.LocalPort);
                var remotePort = BinaryPrimitives.ReverseEndianness((ushort)row.RemotePort);
                resultRows.Add(new WindowsTcpRow(localAddress, localPort, remoteAddress, remotePort, row.OwningPid));
            }

            return resultRows;
        }
        catch
        {
            return Array.Empty<WindowsTcpRow>();
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr tcpTable, ref int outBufLen, bool sort, int ipVersion, TcpTableClass tableClass, uint reserved);

    private enum TcpTableClass
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
    private readonly struct MibTcpRowOwnerPid
    {
        public readonly uint State;
        public readonly uint LocalAddr;
        public readonly uint LocalPort;
        public readonly uint RemoteAddr;
        public readonly uint RemotePort;
        public readonly uint OwningPid;
    }
}
