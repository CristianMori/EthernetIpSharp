using System.Net;

namespace EthernetIPSharp.Connections;

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
    /// <summary>Class 6 — CIP Safety transport with safety-framed data.</summary>
    Class6 = 6,
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

    /// <summary>
    /// Connection data carried in the Forward Open path's Simple Data
    /// Segment (0x80). For a Generic Ethernet Module this is the config
    /// assembly payload the originator pushes at FwdOpen. Empty if absent.
    /// </summary>
    public ReadOnlyMemory<byte> ConfigData { get; init; } = ReadOnlyMemory<byte>.Empty;

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
    public uint EncapsulationSequenceNumber { get; set; } = 1;

    /// <summary>CIP sequence count for Class 1 transport (16-bit, prepended to data).</summary>
    public ushort CipSequenceCount { get; set; }

    // --- Safety ---

    /// <summary>True if this is a CIP Safety connection (detected by 0x50 safety segment in Forward Open path).</summary>
    public bool IsSafety { get; set; }

    /// <summary>Safety wire format (Base or Extended). Only valid when IsSafety is true.</summary>
    public byte SafetyFormat { get; set; }

    /// <summary>CRC-S1 seed for data WE produce (T→O). Computed from target identity + SVInst.</summary>
    public byte SafetyPidSeedS1 { get; set; }

    /// <summary>CRC-S3 seed for data WE produce (T→O). Computed from target identity + SVInst.</summary>
    public ushort SafetyPidSeedS3 { get; set; }

    /// <summary>CRC-S5 seed for data WE produce (T→O). Computed from target identity + SVInst.</summary>
    public uint SafetyPidSeedS5 { get; set; }

    /// <summary>CRC-S1 seed for data ORIGINATOR produces (O→T). Computed from originator identity + connSerial.</summary>
    public byte SafetyOriginatorPidSeedS1 { get; set; }

    /// <summary>CRC-S3 seed for data ORIGINATOR produces (O→T). Computed from originator identity + connSerial.</summary>
    public ushort SafetyOriginatorPidSeedS3 { get; set; }

    /// <summary>CRC-S5 seed for data ORIGINATOR produces (O→T). Computed from originator identity + connSerial.</summary>
    public uint SafetyOriginatorPidSeedS5 { get; set; }

    /// <summary>CRC-S3 seed computed from CID (originator identity + connSerial). Used for time coordination CRC.</summary>
    public ushort SafetyCidSeedS3 { get; set; }

    /// <summary>CRC-S5 seed computed from CID (originator identity + connSerial). Used for Extended Format time coordination CRC.</summary>
    public uint SafetyCidSeedS5 { get; set; }

    /// <summary>Last observed Ping_Count from the producer's mode byte.</summary>
    public byte SafetyLastPingCount { get; set; } = 0xFF; // 0xFF = not yet received

    /// <summary>True if a time coordination response needs to be sent.</summary>
    public bool SafetyNeedTimeCoordination { get; set; }

    /// <summary>Safety Validator instance ID — used as tgtCnxnSerNum in application reply and as cnxnSerNum in PID.</summary>
    public ushort SafetyValidatorInstanceId { get; set; }

    /// <summary>Initial Timestamp from safety segment request — echoed in client app reply.</summary>
    public ushort SafetyInitialTimestamp { get; set; }

    /// <summary>Initial Rollover Value from safety segment request — echoed in client app reply.</summary>
    public ushort SafetyInitialRolloverValue { get; set; }

    /// <summary>True after consumer sends a valid time coordination message. Until then, producer sends Idle/timestamp=0.</summary>
    public bool SafetyConsumerActive { get; set; }

    /// <summary>True after PLC transitions to run=1 on this connection. Used to trigger partner connection production.</summary>
    public bool SafetyPlcRunning { get; set; }

    /// <summary>Raw safety network segment data from the Forward Open connection path.</summary>
    public ReadOnlyMemory<byte> SafetySegmentData { get; init; }

    /// <summary>Rollover count for Extended Format timestamp tracking.</summary>
    public ushort SafetyRolloverCount { get; set; }

    /// <summary>Safety timestamp counter (128µs resolution).</summary>
    public ushort SafetyTimestamp { get; set; }

    /// <summary>Full 64-bit tick count of last sent corrected timestamp (no wrap). Used to detect backward jumps without modular ambiguity.</summary>
    public long SafetyLastSentTicks { get; set; }

    /// <summary>Safety ping count for time coordination (cycles 0-3).</summary>
    public byte SafetyPingCount { get; set; }

    /// <summary>High-res timestamp (Stopwatch ticks) when production started.</summary>
    public long SafetyProductionStartTicks { get; set; }

    /// <summary>High-res timestamp (Stopwatch ticks) of last ping count change.</summary>
    public long SafetyLastPingChangeTicks { get; set; }

    /// <summary>Ping interval in microseconds (PingIntervalMultiplier × TtoORpi).</summary>
    public long SafetyPingIntervalUs { get; set; }

    /// <summary>Consumer_Time_Correction_Value — offset added to producer timestamp (128µs ticks).</summary>
    public ushort SafetyConsumerTimeCorrectionValue { get; set; }

    /// <summary>Target CTCV from the most recent TCOO. The producer slews
    /// SafetyConsumerTimeCorrectionValue toward this value gradually (one tick
    /// per frame) so a single late TCOO can never cause a sudden timestamp jump
    /// that the consumer might reject.</summary>
    public ushort SafetyConsumerTimeCorrectionGoal { get; set; }

    /// <summary>Last timestamp we produced (before correction), for TCOO processing.</summary>
    public ushort SafetyLastProducedTimestamp { get; set; }

    /// <summary>Connection_Correction_Constant — computed once at connection open (128µs ticks).</summary>
    public ushort SafetyConnectionCorrectionConstant { get; set; }

    /// <summary>True after first TCOO has been processed for time correction (skip drift check on first).</summary>
    public bool SafetyTimeCorrectionInitialized { get; set; }

    /// <summary>Stopwatch tick at the moment ProduceIoData last sent a data
    /// frame. Used by the TCOO handler to reject TCOOs that arrive
    /// anomalously late after our send (those carry CTV biased by the delay,
    /// which would produce a spurious CTCV jump).</summary>
    public long SafetyLastFrameSentTicks { get; set; }

    /// <summary>Stopwatch tick until which to emit per-frame startup trace logs
    /// (mode/ts/CTCV on every send and recv). Set when the safety connection
    /// is configured; helps diagnose the short 0.1–1s connection failures
    /// that happen at restart. Zero = trace disabled.</summary>
    public long SafetyStartupTraceUntilTicks { get; set; }

    /// <summary>Rollover count for the ORIGINATOR's (incoming) wire timestamp.
    /// Separate from SafetyRolloverCount (which tracks our outgoing wire ts).
    /// Both start at SafetyInitialRolloverValue but increment independently —
    /// originator's increments when PLC's incoming wire ts wraps 0xFFFF→0x0000,
    /// ours increments when our outgoing wire ts wraps. Required because
    /// Extended-Format CRC validation depends on rolloverCount and the
    /// producer's clock can diverge from ours during startup.</summary>
    public ushort SafetyOriginatorRolloverCount { get; set; }

    /// <summary>Last incoming wire timestamp seen. Used to detect wrap and
    /// increment SafetyOriginatorRolloverCount.</summary>
    public ushort SafetyOriginatorLastTs { get; set; }

    /// <summary>True after SafetyOriginatorRolloverCount has been seeded.</summary>
    public bool SafetyOriginatorRolloverInitialized { get; set; }

    // --- State ---

    /// <summary>Current connection state.</summary>
    public ConnectionState State { get; set; } = ConnectionState.Established;

    /// <summary>Timestamp of the last received O→T packet (UTC). Used for watchdog timeout.</summary>
    public DateTime LastReceivedUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Per CIP Vol 1 §3-4.5.2, the consumer's connection-timeout timer must
    /// not start until the first inbound frame arrives. Without this flag the
    /// watchdog would count from FwdOpen accept and close the connection
    /// whenever the producer takes longer than `rpi * timeout_multiplier` to
    /// start streaming — common on scanners that establish both directions
    /// of a paired safety connection before starting either producer.
    /// </summary>
    public bool FirstReceived { get; set; } = false;

    // --- Timers (managed by VirtualDevice) ---

    /// <summary>Watchdog timer — fires to check if O→T data has stopped arriving.</summary>
    internal Timer? WatchdogTimer { get; set; }

    /// <summary>Production thread — high-res timing for T→O cyclic data.</summary>
    /// <summary>True if a production thread is running for this connection.</summary>
    public bool IsProducing => ProductionThread != null;

    internal Thread? ProductionThread { get; set; }

    /// <summary>Cancellation for production thread.</summary>
    internal CancellationTokenSource? ProductionCts { get; set; }

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
        ProductionCts?.Cancel();
        State = ConnectionState.NonExistent;
    }
}
