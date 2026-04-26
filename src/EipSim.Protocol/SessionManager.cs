using System.Collections.Concurrent;

namespace EipSim.Protocol;

public sealed class SessionManager : ISessionManager
{
    private readonly ConcurrentDictionary<uint, SessionInfo> _sessions = new();
    private uint _nextHandle = 1;

    public uint Register()
    {
        uint handle = Interlocked.Increment(ref _nextHandle);
        _sessions[handle] = new SessionInfo { Handle = handle, CreatedUtc = DateTime.UtcNow };
        return handle;
    }

    public bool Unregister(uint handle) => _sessions.TryRemove(handle, out _);

    public bool IsValid(uint handle) => _sessions.ContainsKey(handle);

    public int ActiveCount => _sessions.Count;
}

public sealed class SessionInfo
{
    public uint Handle { get; init; }
    public DateTime CreatedUtc { get; init; }
}
