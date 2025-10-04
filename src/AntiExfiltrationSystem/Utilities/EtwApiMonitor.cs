using System.Diagnostics.Eventing.Reader;
using AntiExfiltrationSystem.Memory;

namespace AntiExfiltrationSystem.Utilities;

public static class EtwApiMonitor
{
    public static IReadOnlyList<ApiCallRecord> FetchRecentApiCalls(int processId)
    {
        var records = new List<ApiCallRecord>();
        var queryString = $"*[System[(EventID=1) and TimeCreated[timediff(@SystemTime) <= 5000]]] and *[EventData[Data[@Name='ProcessID']={processId}]]";
        var query = new EventLogQuery("Microsoft-Windows-Kernel-Audit-API-Calls/Operational", PathType.LogName, queryString);

        try
        {
            using var reader = new EventLogReader(query);
            for (EventRecord? record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
            {
                using (record)
                {
                    var functionName = record.Properties.Count > 1 ? record.Properties[1].Value?.ToString() ?? "" : "";
                    records.Add(new ApiCallRecord
                    {
                        FunctionName = functionName,
                        Timestamp = record.TimeCreated ?? DateTime.UtcNow
                    });
                }
            }
        }
        catch
        {
        }

        return records;
    }
}
