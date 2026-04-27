using System.Collections.Concurrent;

namespace EipSim.Protocol;

/// <summary>
/// Manages EtherNet/IP encapsulation sessions.
/// Each TCP connection registers a session via RegisterSession and receives a unique handle.
/// The handle is validated on every SendRRData request and released on UnregisterSession or disconnect.
/// Thread-safe — multiple TCP connections may register concurrently.
/// </summary>
public sealed class SessionManager : ISessionManager
{
    /// <summary>Active sessions keyed by handle. SessionInfo stored for future use (e.g. inactivity timeout).</summary>
    private readonly ConcurrentDictionary<uint, SessionInfo> _sessions = new();

    /// <summary>Counter for generating unique session handles. Starts at 0 so first Increment returns 1.</summary>
    private uint _nextHandle;

    /// <summary>Allocate a new session and return its handle.</summary>
    public uint Register()
    {
        uint handle = Interlocked.Increment(ref _nextHandle);
        _sessions[handle] = new SessionInfo { Handle = handle, CreatedUtc = DateTime.UtcNow };
        return handle;
    }

    /// <summary>Release a session. Returns true if the session existed.</summary>
    public bool Unregister(uint handle) => _sessions.TryRemove(handle, out _);

    /// <summary>Check if a session handle is currently valid (registered and not unregistered).</summary>
    public bool IsValid(uint handle) => _sessions.ContainsKey(handle);

    /// <summary>Number of currently active sessions.</summary>
    public int ActiveCount => _sessions.Count;
}

/// <summary>
/// Information about an active encapsulation session.
/// Currently stores creation time for potential inactivity timeout use.
/// </summary>
public sealed class SessionInfo
{
    /// <summary>The session handle assigned to this session.</summary>
    public uint Handle { get; init; }

    /// <summary>When this session was created (UTC).</summary>
    public DateTime CreatedUtc { get; init; }
}
