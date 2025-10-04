using System.Buffers;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using AntiExfiltrationSystem.Utilities;

namespace AntiExfiltrationSystem.Memory;

[SupportedOSPlatform("windows")]
public sealed class ProductionMemoryAnalyzer
{
    public MemoryAnalysisResult AnalyzeProcessMemory(int processId)
    {
        var process = Process.GetProcessById(processId);
        using var safeHandle = OpenProcessHandle(processId);
        var regions = EnumerateRegions(safeHandle);
        var strings = ExtractStrings(safeHandle, regions);
        var hooks = DetectHooks(process);
        var apiCalls = EtwApiMonitor.FetchRecentApiCalls(processId);
        var links = CorrelateDataLinks(processId, strings);

        return new MemoryAnalysisResult
        {
            MemoryRegions = regions,
            SuspiciousStrings = strings,
            ApiHooks = hooks,
            ApiCalls = apiCalls,
            DataLinks = links
        };
    }

    private static SafeProcessHandle OpenProcessHandle(int processId)
    {
        var handle = NativeMethods.OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VirtualMemoryRead, false, processId);
        if (handle.IsInvalid)
        {
            throw new InvalidOperationException($"Unable to open process handle for PID {processId}.");
        }

        return handle;
    }

    private static List<MemoryRegion> EnumerateRegions(SafeProcessHandle handle)
    {
        var regions = new List<MemoryRegion>();
        var address = IntPtr.Zero;
        var mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
        while (NativeMethods.VirtualQueryEx(handle, address, out var mbi, mbiSize) != 0)
        {
            if (mbi.State == PageState.Commit)
            {
                regions.Add(new MemoryRegion
                {
                    BaseAddress = mbi.BaseAddress,
                    Size = (int)mbi.RegionSize,
                    Protection = mbi.Protect.ToString()
                });
            }

            address = new IntPtr(mbi.BaseAddress.ToInt64() + (long)mbi.RegionSize);
        }

        return regions;
    }

    private static List<string> ExtractStrings(SafeProcessHandle handle, IReadOnlyList<MemoryRegion> regions)
    {
        var result = new List<string>();
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            foreach (var region in regions)
            {
                var address = region.BaseAddress;
                var remaining = region.Size;
                while (remaining > 0)
                {
                    var toRead = Math.Min(buffer.Length, remaining);
                    if (NativeMethods.ReadProcessMemory(handle, address, buffer, toRead, out var bytesRead) && bytesRead > 0)
                    {
                        var text = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        foreach (var candidate in text.Split('\0', StringSplitOptions.RemoveEmptyEntries))
                        {
                            if (SensitiveDataDetector.IsSensitive(candidate))
                            {
                                result.Add(candidate);
                            }
                        }
                    }

                    address = new IntPtr(address.ToInt64() + bytesRead);
                    remaining -= bytesRead;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return result.Distinct().Take(500).ToList();
    }

    private static List<ApiHookRecord> DetectHooks(Process process)
    {
        var hooks = new List<ApiHookRecord>();
        foreach (ProcessModule module in process.Modules)
        {
            var moduleBase = module.BaseAddress;
            var pe = new PeImage(moduleBase);
            hooks.AddRange(pe.FindImports().Where(h => h.IsHooked).Select(h => new ApiHookRecord
            {
                FunctionName = h.Function,
                Address = h.Address
            }));
        }

        return hooks;
    }

    private static List<MemoryDataLink> CorrelateDataLinks(int processId, IReadOnlyList<string> strings)
    {
        var links = new List<MemoryDataLink>();
        var packets = PacketRepository.GetPacketsByProcess(processId);
        foreach (var str in strings)
        {
            var matches = packets
                .Where(p => Encoding.UTF8.GetString(p.Payload).Contains(str, StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Payload)
                .ToList();
            if (matches.Count > 0)
            {
                links.Add(new MemoryDataLink
                {
                    Pattern = str,
                    MatchingPackets = matches,
                    Confidence = Math.Min(100, 50 + str.Length)
                });
            }
        }

        return links;
    }
}

internal sealed class PeImage
{
    private readonly IntPtr _baseAddress;

    public PeImage(IntPtr baseAddress)
    {
        _baseAddress = baseAddress;
    }

    public IEnumerable<ImportEntry> FindImports()
    {
        var dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(_baseAddress);
        var ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(_baseAddress + dosHeader.e_lfanew);
        var importsDirectory = ntHeaders.OptionalHeader.DataDirectory[1];
        if (importsDirectory.Size == 0)
        {
            yield break;
        }

        var descriptor = _baseAddress + (int)importsDirectory.VirtualAddress;
        while (true)
        {
            var importDescriptor = Marshal.PtrToStructure<IMAGE_IMPORT_DESCRIPTOR>(descriptor);
            if (importDescriptor.Name == 0)
            {
                break;
            }

            var moduleName = Marshal.PtrToStringAnsi(_baseAddress + (int)importDescriptor.Name) ?? string.Empty;
            var thunk = _baseAddress + (int)importDescriptor.FirstThunk;
            while (true)
            {
                var functionPtr = Marshal.ReadIntPtr(thunk);
                if (functionPtr == IntPtr.Zero)
                {
                    break;
                }

                var isHooked = !NativeMethods.IsAddressInModule(functionPtr, _baseAddress);
                yield return new ImportEntry(moduleName, functionPtr, isHooked);
                thunk += IntPtr.Size;
            }

            descriptor += Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
        }
    }
}

internal readonly record struct ImportEntry(string Function, IntPtr Address, bool IsHooked);

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_DOS_HEADER
{
    public short e_magic;
    public short e_cblp;
    public short e_cp;
    public short e_crlc;
    public short e_cparhdr;
    public short e_minalloc;
    public short e_maxalloc;
    public short e_ss;
    public short e_sp;
    public short e_csum;
    public short e_ip;
    public short e_cs;
    public short e_lfarlc;
    public short e_ovno;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public short[] e_res1;
    public short e_oemid;
    public short e_oeminfo;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
    public short[] e_res2;
    public int e_lfanew;
}

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_NT_HEADERS
{
    public int Signature;
    public IMAGE_FILE_HEADER FileHeader;
    public IMAGE_OPTIONAL_HEADER OptionalHeader;
}

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_FILE_HEADER
{
    public short Machine;
    public short NumberOfSections;
    public int TimeDateStamp;
    public int PointerToSymbolTable;
    public int NumberOfSymbols;
    public short SizeOfOptionalHeader;
    public short Characteristics;
}

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_OPTIONAL_HEADER
{
    public short Magic;
    public byte MajorLinkerVersion;
    public byte MinorLinkerVersion;
    public int SizeOfCode;
    public int SizeOfInitializedData;
    public int SizeOfUninitializedData;
    public int AddressOfEntryPoint;
    public int BaseOfCode;
    public IntPtr ImageBase;
    public int SectionAlignment;
    public int FileAlignment;
    public short MajorOperatingSystemVersion;
    public short MinorOperatingSystemVersion;
    public short MajorImageVersion;
    public short MinorImageVersion;
    public short MajorSubsystemVersion;
    public short MinorSubsystemVersion;
    public int Win32VersionValue;
    public int SizeOfImage;
    public int SizeOfHeaders;
    public int CheckSum;
    public short Subsystem;
    public short DllCharacteristics;
    public IntPtr SizeOfStackReserve;
    public IntPtr SizeOfStackCommit;
    public IntPtr SizeOfHeapReserve;
    public IntPtr SizeOfHeapCommit;
    public int LoaderFlags;
    public int NumberOfRvaAndSizes;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public IMAGE_DATA_DIRECTORY[] DataDirectory;
}

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_DATA_DIRECTORY
{
    public uint VirtualAddress;
    public uint Size;
}

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_IMPORT_DESCRIPTOR
{
    public uint Characteristics;
    public uint TimeDateStamp;
    public uint ForwarderChain;
    public uint Name;
    public uint FirstThunk;
}

[StructLayout(LayoutKind.Sequential)]
internal struct MEMORY_BASIC_INFORMATION
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public PageProtection Protect;
    public IntPtr RegionSize;
    public PageState State;
    public PageProtection AllocationProtect;
    public PageType Type;
}

internal enum PageState
{
    Commit = 0x1000,
    Reserve = 0x2000,
    Free = 0x10000
}

[Flags]
internal enum PageProtection
{
    ExecuteReadWrite = 0x40,
    ReadWrite = 0x04,
    ExecuteRead = 0x20,
    ReadOnly = 0x02
}

internal enum PageType
{
    Image = 0x1000000,
    Mapped = 0x40000,
    Private = 0x20000
}

internal sealed class SafeProcessHandle : SafeHandle
{
    public SafeProcessHandle() : base(IntPtr.Zero, true)
    {
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        return NativeMethods.CloseHandle(handle);
    }
}

internal static class NativeMethods
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeProcessHandle OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(SafeProcessHandle hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(SafeProcessHandle hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    public static bool IsAddressInModule(IntPtr address, IntPtr moduleBase)
    {
        var relative = address.ToInt64() - moduleBase.ToInt64();
        return relative >= 0 && relative < 0x1000000;
    }
}

[Flags]
internal enum ProcessAccessFlags
{
    QueryInformation = 0x400,
    VirtualMemoryRead = 0x10
}
