using System.Collections.Concurrent;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;

namespace DnSpyMcp.Core;

public class AssemblyCache
{
    private record CacheEntry(CSharpDecompiler Decompiler, PEFile PEFile, DateTime LoadedAt);
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();

    public (CSharpDecompiler decompiler, PEFile peFile) GetOrLoad(string path)
    {
        var abs = Path.GetFullPath(path);
        if (!File.Exists(abs)) throw new FileNotFoundException($"Assembly not found: {abs}");
        var mtime = File.GetLastWriteTimeUtc(abs);
        var key = $"{abs}|{mtime:O}";
        if (_cache.TryGetValue(key, out var entry)) return (entry.Decompiler, entry.PEFile);

        var settings = new DecompilerSettings
        {
            ThrowOnAssemblyResolveErrors = false,
            RemoveDeadCode = false,
            ShowXmlDocumentation = true,
            LoadInMemory = false,
        };
        var decompiler = new CSharpDecompiler(abs, settings);
        var peFile = new PEFile(abs, System.Reflection.PortableExecutable.PEStreamOptions.Default);
        var newEntry = new CacheEntry(decompiler, peFile, DateTime.UtcNow);
        _cache[key] = newEntry;


        foreach (var k in _cache.Keys.Where(k => k.StartsWith(abs + "|") && k != key).ToList())
            _cache.TryRemove(k, out _);

        return (decompiler, peFile);
    }

    public void Evict(string path)
    {
        var abs = Path.GetFullPath(path);
        foreach (var k in _cache.Keys.Where(k => k.StartsWith(abs + "|")).ToList())
            _cache.TryRemove(k, out _);
    }
}
