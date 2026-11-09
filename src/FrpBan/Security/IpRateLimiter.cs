namespace FrpBan.Security;

/// <summary>Bounded per-IP fixed-window limiter; all state changes share one short lock.</summary>
internal sealed class IpRateLimiter(int limit, int maxAddresses = 4096)
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Window> _windows = new(StringComparer.Ordinal);
    private long _nextCleanup;

    public bool TryAcquire(string address)
    {
        var now = Environment.TickCount64;
        lock (_gate)
        {
            if (now >= _nextCleanup)
            {
                foreach (var key in _windows.Where(pair => now - pair.Value.Start >= 60_000)
                             .Select(pair => pair.Key).ToArray())
                    _windows.Remove(key);
                _nextCleanup = now + 60_000;
            }

            if (!_windows.TryGetValue(address, out var window))
            {
                if (_windows.Count >= maxAddresses)
                    return false;
                window = new Window(now);
                _windows.Add(address, window);
            }
            if (now - window.Start >= 60_000)
            {
                window.Start = now;
                window.Count = 0;
            }
            return ++window.Count <= limit;
        }
    }

    private sealed class Window(long start)
    {
        public long Start = start;
        public long Count;
    }
}
