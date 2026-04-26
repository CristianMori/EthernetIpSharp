using System.Net;

namespace EipSim.Connections;

public enum ConnectionState { NonExistent, Established, TimedOut }
public enum TransportClass : byte { Class0 = 0, Class1 = 1 }

/// <summary>
/// Represents a single I/O connection established via Forward Open.
/// </summary>
public sealed class IoConnection : IDisposable
{
    // Connection identity (the "connection triad")
    public ushort ConnectionSerialNumber { get; init; }
    public ushort OriginatorVendorId { get; init; }
    public uint OriginatorSerialNumber { get; init; }

    // Connection IDs on the wire
    public uint OtoTConnectionId { get; init; }  // Scanner sends to us with this ID
    public uint TtoOConnectionId { get; init; }  // We send to scanner with this ID

    // Assembly references (instance IDs)
    public uint ConsumedAssemblyInstance { get; init; }  // O→T (what PLC sends us)
    public uint ProducedAssemblyInstance { get; init; }  // T→O (what we send PLC)
    public uint ConfigAssemblyInstance { get; init; }

    // Connection parameters
    public uint OtoTRpi { get; init; }  // microseconds
    public uint TtoORpi { get; init; }  // microseconds
    public ushort OtoTSize { get; init; }
    public ushort TtoOSize { get; init; }
    public TransportClass TransportClass { get; init; }
    public byte TimeoutMultiplier { get; init; }

    // Computed timeout: RPI * multiplier_value
    public TimeSpan ConnectionTimeout =>
        TimeSpan.FromMicroseconds(OtoTRpi * GetMultiplierValue(TimeoutMultiplier));

    // Network
    public IPEndPoint? RemoteEndpoint { get; set; }
    public ushort RemoteUdpPort { get; set; } = 0x08AE; // default registered port

    // Sequence tracking
    public uint EncapsulationSequenceNumber { get; set; }
    public ushort CipSequenceCount { get; set; }

    // State
    public ConnectionState State { get; set; } = ConnectionState.Established;
    public DateTime LastReceivedUtc { get; set; } = DateTime.UtcNow;

    // Timers
    public Timer? WatchdogTimer { get; set; }
    public Timer? ProductionTimer { get; set; }

    private static int GetMultiplierValue(byte multiplier) => multiplier switch
    {
        0 => 4,
        1 => 8,
        2 => 16,
        3 => 32,
        4 => 64,
        5 => 128,
        6 => 256,
        7 => 512,
        _ => 4,
    };

    public void Dispose()
    {
        WatchdogTimer?.Dispose();
        ProductionTimer?.Dispose();
        State = ConnectionState.NonExistent;
    }
}
