using AntiExfiltration.Infrastructure;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace AntiExfiltration.Core;

public sealed class BehaviorEngine
{
    private readonly SecureLogger _logger;
    private readonly BehaviorConfiguration _configuration;
    private readonly ConcurrentDictionary<int, BehaviorScore> _scores = new();

    public BehaviorEngine(SecureLogger logger, BehaviorConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public BehaviorConfiguration Configuration => _configuration;

    public BehaviorScore UpdateScore(int processId, Func<BehaviorScore, BehaviorScore> update)
    {
        var score = _scores.AddOrUpdate(processId, pid => update(new BehaviorScore(pid)), (pid, existing) => update(existing));
        _logger.Log(new
        {
            timestamp = DateTimeOffset.UtcNow,
            eventType = "behaviorScore",
            processId,
            score.Total,
            score.Level
        });
        return score;
    }

    public BehaviorScore GetScore(int processId)
        => _scores.TryGetValue(processId, out var score) ? score : new BehaviorScore(processId);

    public IEnumerable<BehaviorScore> GetAllScores() => _scores.Values;

    public sealed record BehaviorScore(int ProcessId)
    {
        public int Total { get; init; }
        public List<string> Indicators { get; init; } = new();
        public BehaviorLevel Level { get; init; } = BehaviorLevel.Normal;

        public BehaviorScore WithIndicator(string indicator, int delta, BehaviorConfiguration configuration)
        {
            var total = Total + delta;
            var level = total >= configuration.CriticalThreshold
                ? BehaviorLevel.Critical
                : total >= configuration.MaliciousThreshold
                    ? BehaviorLevel.Malicious
                    : total >= configuration.SuspiciousThreshold
                        ? BehaviorLevel.Suspicious
                        : BehaviorLevel.Normal;

            var indicators = Indicators.ToList();
            indicators.Add(indicator);

            return this with { Total = total, Level = level, Indicators = indicators };
        }
    }

    public enum BehaviorLevel
    {
        Normal,
        Suspicious,
        Malicious,
        Critical
    }
}
