using System;
using System.Collections.Generic;
using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Common;
using AntiExfiltration.Core.Context;

namespace AntiExfiltration.Core.Policy;

/// <summary>
/// Estimates Shannon entropy to detect high-entropy blobs indicative of encryption or compression.
/// </summary>
public sealed class EntropyAnalyzer : IAnalyzer
{
    private readonly double _threshold;

    public EntropyAnalyzer(double threshold = 7.5)
    {
        _threshold = threshold;
    }

    public AnalyzerFinding Analyze(RawPacket packet, ProcessInfo process)
    {
        if (packet.Payload.Length == 0)
        {
            return CreateBenignResult(process, "Empty payload");
        }

        var entropy = CalculateShannonEntropy(packet.Payload);
        if (entropy >= _threshold)
        {
            return new AnalyzerFinding(
                Analyzer: nameof(EntropyAnalyzer),
                IsSensitive: true,
                Risk: RiskLevel.High,
                Reason: $"High entropy payload ({entropy:F2})",
                Signals: new Dictionary<string, object?>
                {
                    ["Entropy"] = entropy,
                    ["Size"] = packet.Payload.Length
                },
                Process: process);
        }

        return CreateBenignResult(process, $"Entropy below threshold ({entropy:F2})");
    }

    private static AnalyzerFinding CreateBenignResult(ProcessInfo process, string reason)
    {
        return new AnalyzerFinding(
            Analyzer: nameof(EntropyAnalyzer),
            IsSensitive: false,
            Risk: RiskLevel.Low,
            Reason: reason,
            Signals: new Dictionary<string, object?>(),
            Process: process);
    }

    private static double CalculateShannonEntropy(byte[] data)
    {
        Span<int> frequencies = stackalloc int[256];
        foreach (var b in data)
        {
            frequencies[b]++;
        }

        double entropy = 0;
        var length = data.Length;
        for (var i = 0; i < frequencies.Length; i++)
        {
            if (frequencies[i] == 0)
            {
                continue;
            }

            var probability = frequencies[i] / (double)length;
            entropy -= probability * Math.Log(probability, 2);
        }

        return entropy;
    }
}
