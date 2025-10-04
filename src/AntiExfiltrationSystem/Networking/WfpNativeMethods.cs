using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace AntiExfiltrationSystem.Networking;

[SupportedOSPlatform("windows")]
internal static class WfpNativeMethods
{
    public const uint RPC_C_AUTHN_WINNT = 10;

    [DllImport("Fwpuclnt.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern uint FwpmEngineOpen0(
        string? serverName,
        uint authnService,
        IntPtr? authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("Fwpuclnt.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("Fwpuclnt.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern uint FwpsCalloutRegister0(
        IntPtr deviceObject,
        ref FWPS_CALLOUT0 callout,
        out uint calloutId);

    [DllImport("Fwpuclnt.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern uint FwpmCalloutAdd0(
        IntPtr engineHandle,
        ref FWPM_CALLOUT0 callout,
        IntPtr sd,
        out Guid id);

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPS_CALLOUT0
    {
        public Guid CalloutKey;
        public IntPtr ClassifyFn;
        public IntPtr NotifyFn;
        public IntPtr FlowDeleteFn;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_DISPLAY_DATA0
    {
        public IntPtr Name;
        public IntPtr Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_CALLOUT0
    {
        public Guid CalloutKey;
        public FWPM_DISPLAY_DATA0 DisplayData;
        public uint ApplicableLayer;
        public uint CalloutFlags;
        public Guid ProviderKey;
        public Guid ApplicableSublayerKey;
        public Guid ApplicableLayerKey;
    }
}
