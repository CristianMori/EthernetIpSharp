namespace EipSim.Protocol;

/// <summary>
/// Encapsulation session management abstraction.
/// Mock for testing session validation and error paths without TCP.
/// </summary>
public interface ISessionManager
{
    uint Register();
    bool Unregister(uint handle);
    bool IsValid(uint handle);
    int ActiveCount { get; }
}
