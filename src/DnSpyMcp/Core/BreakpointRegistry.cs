using System.Collections.Concurrent;

namespace DnSpyMcp.Core;

public record Breakpoint(
    string Id,
    string AssemblyPath,
    string TypeName,
    string MethodName,
    int? ILOffset,
    DateTime CreatedAt
);

public class BreakpointRegistry
{
    private readonly ConcurrentDictionary<string, Breakpoint> _bps = new();
    private int _counter = 0;

    public Breakpoint Add(string assemblyPath, string typeName, string methodName, int? ilOffset)
    {
        var id = $"bp{Interlocked.Increment(ref _counter):D3}";
        var bp = new Breakpoint(id, Path.GetFullPath(assemblyPath), typeName, methodName, ilOffset, DateTime.UtcNow);
        _bps[id] = bp;
        return bp;
    }

    public IReadOnlyList<Breakpoint> All() => _bps.Values.OrderBy(b => b.CreatedAt).ToList();

    public Breakpoint? Get(string id) => _bps.TryGetValue(id, out var bp) ? bp : null;

    public bool Remove(string id) => _bps.TryRemove(id, out _);

    public int RemoveByAssembly(string assemblyPath)
    {
        var abs = Path.GetFullPath(assemblyPath);
        var keys = _bps.Where(kv => kv.Value.AssemblyPath == abs).Select(kv => kv.Key).ToList();
        foreach (var k in keys) _bps.TryRemove(k, out _);
        return keys.Count;
    }

    public int RemoveAll()
    {
        var count = _bps.Count;
        _bps.Clear();
        return count;
    }
}
