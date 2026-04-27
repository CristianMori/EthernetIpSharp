using System.Net;

namespace EipSim.Connections;

/// <summary>State of an I/O connection.</summary>
public enum ConnectionState
{
    /// <summary>Connection does not exist or has been closed.</summary>
    NonExistent,
    /// <summary>Connection is active and exchanging data.</summary>
    Established,
    /// <summary>Connection timed out due to missing packets.</summary>
    TimedOut,
}

/// <summary>CIP transport class for I/O connections.</summary>
public enum TransportClass : byte
{
    /// <summary>Class 0 — no sequence count in data.</summary>
    Class0 = 0,
    /// <summary>Class 1 — 16-bit sequence count prepended to data.</summary>
    Class1 = 1,
}

/// <summary>
/// Represents a single I/O connection established via Forward Open.
/// Holds connection identity, parameters, sequence counters, and production/watchdog timers.
/// Created by ConnectionManagerObject, managed by VirtualDevice.
/// </summary>
public sealed class IoConnection : IDisposable
{
    // --- Connection identity (the "connection triad") ---

    /// <summary>Unique serial number chosen by the originator for this connection.</summary>
    public ushort ConnectionSerialNumber { get; init; }

    /// <summary>Vendor ID of the originator (scanner/PLC).</summary>
    public ushort OriginatorVendorId { get; init; }

    /// <summary>Serial number of the originator device.</summary>
    public uint OriginatorSerialNumber { get; init; }

    // --- Connection IDs on the wire ---

    /// <summary>O→T connection ID — the scanner uses this in UDP packets it sends to us.</summary>
    public uint OtoTConnectionId { get; init; }

    /// <summary>T→O connection ID — we use this in UDP packets we send to the scanner.</summary>
    public uint TtoOConnectionId { get; init; }

    // --- Assembly references (instance IDs) ---

    /// <summary>Assembly instance for O→T consumed data (what the PLC sends us).</summary>
    public uint ConsumedAssemblyInstance { get; init; }

    /// <summary>Assembly instance for T→O produced data (what we send to the PLC).</summary>
    public uint ProducedAssemblyInstance { get; init; }

    /// <summary>Configuration assembly instance.</summary>
    public uint ConfigAssemblyInstance { get; init; }

    // --- Connection parameters ---

    /// <summary>O→T Requested Packet Interval in microseconds.</summary>
    public uint OtoTRpi { get; init; }

    /// <summary>T→O Requested Packet Interval in microseconds.</summary>
    public uint TtoORpi { get; init; }

    /// <summary>O→T connection size in bytes (on wire, includes seq count).</summary>
    public ushort OtoTSize { get; init; }

    /// <summary>T→O connection size in bytes (on wire, includes seq count).</summary>
    public ushort TtoOSize { get; init; }

    /// <summary>Transport class (Class 0 or Class 1).</summary>
    public TransportClass TransportClass { get; init; }

    /// <summary>Timeout multiplier code (0=x4, 1=x8, 2=x16, ... 7=x512).</summary>
    public byte TimeoutMultiplier { get; init; }

    /// <summary>Computed connection timeout: RPI × multiplier value.</summary>
    public TimeSpan ConnectionTimeout =>
        TimeSpan.FromMicroseconds(OtoTRpi * GetMultiplierValue(TimeoutMultiplier));

    // --- Network ---

    /// <summary>The scanner's UDP endpoint to send T→O data to. Set after Forward Open.</summary>
    public IPEndPoint? RemoteEndpoint { get; set; }

    // --- Sequence tracking ---

    /// <summary>Encapsulation sequence number for the next T→O UDP packet.</summary>
    public uint EncapsulationSequenceNumber { get; set; }

    /// <summary>CIP sequence count for Class 1 transport (16-bit, prepended to data).</summary>
    public ushort CipSequenceCount { get; set; }

    // --- State ---

    /// <summary>Current connection state.</summary>
    public ConnectionState State { get; set; } = ConnectionState.Established;

    /// <summary>Timestamp of the last received O→T packet (UTC). Used for watchdog timeout.</summary>
    public DateTime LastReceivedUtc { get; set; } = DateTime.UtcNow;

    // --- Timers (managed by VirtualDevice) ---

    /// <summary>Watchdog timer — fires to check if O→T data has stopped arriving.</summary>
    internal Timer? WatchdogTimer { get; set; }

    /// <summary>Production timer — fires at T→O RPI to send cyclic data to the scanner.</summary>
    internal Timer? ProductionTimer { get; set; }

    /// <summary>Map timeout multiplier code to actual multiplier value.</summary>
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

    /// <summary>Dispose timers and set state to NonExistent.</summary>
    public void Dispose()
    {
        WatchdogTimer?.Dispose();
        ProductionTimer?.Dispose();
        State = ConnectionState.NonExistent;
    }
}
