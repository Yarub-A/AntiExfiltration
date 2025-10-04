namespace AntiExfiltrationSystem.Utilities;

public sealed class ConsoleTable
{
    private readonly string[] _headers;
    private readonly List<string[]> _rows = new();

    public ConsoleTable(params string[] headers)
    {
        _headers = headers;
    }

    public ConsoleTable AddRow(params string[] cells)
    {
        if (cells.Length != _headers.Length)
        {
            throw new ArgumentException("Inconsistent cell count", nameof(cells));
        }

        _rows.Add(cells);
        return this;
    }

    public void Clear() => _rows.Clear();

    public void Write()
    {
        var widths = new int[_headers.Length];
        for (var i = 0; i < _headers.Length; i++)
        {
            widths[i] = _headers[i].Length;
        }

        foreach (var row in _rows)
        {
            for (var i = 0; i < row.Length; i++)
            {
                widths[i] = Math.Max(widths[i], row[i].Length);
            }
        }

        var separator = "╔" + string.Join("╦", widths.Select(w => new string('═', w + 2))) + "╗";
        Console.WriteLine(separator);
        Console.WriteLine("║ " + string.Join(" ║ ", _headers.Select((h, i) => h.PadRight(widths[i]))) + " ║");
        Console.WriteLine("╠" + string.Join("╬", widths.Select(w => new string('═', w + 2))) + "╣");

        foreach (var row in _rows)
        {
            Console.WriteLine("║ " + string.Join(" ║ ", row.Select((c, i) => c.PadRight(widths[i]))) + " ║");
        }

        Console.WriteLine("╚" + string.Join("╩", widths.Select(w => new string('═', w + 2))) + "╝");
        Console.WriteLine();
    }
}
