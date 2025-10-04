namespace AntiExfiltrationSystem.Memory;

public sealed class MemoryAnalysisResult
{
    public required IReadOnlyList<MemoryRegion> MemoryRegions { get; init; }
    public required IReadOnlyList<ApiCallRecord> ApiCalls { get; init; }
    public required IReadOnlyList<string> SuspiciousStrings { get; init; }
    public required IReadOnlyList<ApiHookRecord> ApiHooks { get; init; }
    public required IReadOnlyList<MemoryDataLink> DataLinks { get; init; }
}

public sealed class MemoryRegion
{
    public required IntPtr BaseAddress { get; init; }
    public required int Size { get; init; }
    public required string Protection { get; init; }
}

public sealed class ApiCallRecord
{
    public required string FunctionName { get; init; }
    public required DateTime Timestamp { get; init; }
}

public sealed class ApiHookRecord
{
    public required string FunctionName { get; init; }
    public required IntPtr Address { get; init; }
}

public sealed class MemoryDataLink
{
    public required string Pattern { get; init; }
    public required IReadOnlyList<byte[]> MatchingPackets { get; init; }
    public required double Confidence { get; init; }
}
