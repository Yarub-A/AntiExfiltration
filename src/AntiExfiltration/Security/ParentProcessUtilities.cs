using System.ComponentModel;
using System.Runtime.InteropServices;

namespace AntiExfiltration.Security;

public static class ParentProcessUtilities
{
    public static int ParentProcessId => GetParentProcessId(Environment.ProcessId);

    public static int GetParentProcessId(int processId)
    {
        try
        {
            var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.SnapshotFlags.Process, 0);
            if (snapshot == IntPtr.Zero || snapshot == NativeMethods.InvalidHandleValue)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                var entry = new NativeMethods.ProcessEntry32 { dwSize = (uint)Marshal.SizeOf(typeof(NativeMethods.ProcessEntry32)) };
                if (NativeMethods.Process32First(snapshot, ref entry))
                {
                    do
                    {
                        if (entry.th32ProcessID == (uint)processId)
                        {
                            return (int)entry.th32ParentProcessID;
                        }
                    } while (NativeMethods.Process32Next(snapshot, ref entry));
                }
            }
            finally
            {
                NativeMethods.CloseHandle(snapshot);
            }
        }
        catch
        {
            // ignore errors
        }

        return -1;
    }

    private static class NativeMethods
    {
        [Flags]
        public enum SnapshotFlags : uint
        {
            Process = 0x00000002
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessEntry32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        public static readonly IntPtr InvalidHandleValue = new(-1);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Process32First(IntPtr hSnapshot, ref ProcessEntry32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Process32Next(IntPtr hSnapshot, ref ProcessEntry32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
