namespace EthernetIPSharp.Cip;

/// <summary>
/// Shared recursion-depth counter for CIP services that re-enter the dispatcher
/// (Multiple_Service_Packet 0x0A, Unconnected_Send 0x52). A crafted packet that
/// nests one encapsulation inside another — 0x0A ⇒ 0x0A, 0x52 ⇒ 0x52, or
/// mixed 0x0A ⇒ 0x52 ⇒ 0x0A — would otherwise recurse without bound and
/// trigger <see cref="StackOverflowException"/>, which .NET cannot catch and
/// which tears down the host process.
///
/// A single counter across both services closes the mixed-service bypass:
/// capping only MSP would still allow 0x52 ⇒ 0x0A ⇒ 0x52 ⇒ 0x0A chains to
/// recurse to any depth. The cap is per-thread; the dispatcher is thread-safe
/// but a single request is handled on one thread, so a ThreadStatic int is
/// enough and avoids the AsyncLocal overhead.
///
/// Three levels of tolerance is already generous — real clients never nest
/// encapsulation services more than once.
/// </summary>
public static class CipDispatchDepth
{
    /// <summary>Maximum combined nesting depth across all re-entering CIP services.</summary>
    public const int MaxDepth = 3;

    [ThreadStatic]
    private static int _depth;

    /// <summary>True if the per-thread depth has already reached <see cref="MaxDepth"/>.</summary>
    public static bool AtLimit => _depth >= MaxDepth;

    /// <summary>Enter a nested dispatch frame. Pair with <see cref="Exit"/> in a try/finally.</summary>
    public static void Enter() => _depth++;

    /// <summary>Leave a nested dispatch frame.</summary>
    public static void Exit() => _depth--;
}
