using System.Buffers.Binary;
using EthernetIPSharp.Connections;

namespace EthernetIPSharp.Safety;

/// <summary>
/// Configuration for establishing a CIP Safety I/O connection via Forward Open.
/// </summary>
public sealed class SafetyForwardOpenConfig
{
    /// <summary>Assembly instance the originator sends O→T data to (consumed by target).</summary>
    public uint ConsumedAssembly { get; init; }

    /// <summary>Assembly instance the target sends T→O data from (produced by target).</summary>
    public uint ProducedAssembly { get; init; }

    /// <summary>Configuration assembly instance.</summary>
    public uint ConfigAssembly { get; init; }

    /// <summary>O→T actual data size in bytes (before safety framing).</summary>
    public ushort ConsumedDataSize { get; init; }

    /// <summary>T→O actual data size in bytes (before safety framing).</summary>
    public ushort ProducedDataSize { get; init; }

    /// <summary>Requested Packet Interval in microseconds (used for both O→T and T→O if specific RPIs not set).</summary>
    public uint Rpi { get; init; } = 10_000;

    /// <summary>O→T RPI override (if 0, uses Rpi).</summary>
    public uint OtoTRpi { get; init; }

    /// <summary>T→O RPI override (if 0, uses Rpi).</summary>
    public uint TtoORpi { get; init; }

    /// <summary>Safety wire format (Base or Extended).</summary>
    public SafetyFormat Format { get; init; } = SafetyFormat.Base;

    /// <summary>Target Unique Network Identifier.</summary>
    public UniqueNetworkId Tunid { get; init; }

    /// <summary>Originator Unique Network Identifier.</summary>
    public UniqueNetworkId Ounid { get; init; }

    /// <summary>Safety Configuration Identifier (SCID) of the target.</summary>
    public SafetyConfigurationId Scid { get; init; }

    /// <summary>Ping interval multiplier.</summary>
    public ushort PingIntervalMultiplier { get; init; } = 100;

    /// <summary>Time coordination message min multiplier.</summary>
    public ushort TimeCoordMsgMinMultiplier { get; init; } = 50;

    /// <summary>Network time expectation multiplier.</summary>
    public ushort NetworkTimeExpectationMultiplier { get; init; } = 200;

    /// <summary>Timeout multiplier (1-4) for safety segment.</summary>
    public byte TimeoutMultiplier { get; init; } = 2;

    /// <summary>Maximum fault number for Extended Format safety (default 2).</summary>
    public ushort MaxFaultNumber { get; init; } = 2;

    /// <summary>Initial timestamp for Extended Format safety (0xFFFF = cold start).</summary>
    public ushort InitialTimestamp { get; init; } = 0xFFFF;

    /// <summary>Initial rollover value for Extended Format safety (0xFFFF = cold start).</summary>
    public ushort InitialRolloverValue { get; init; } = 0xFFFF;

    /// <summary>Connection timeout multiplier for Forward Open (separate from safety segment). Default 1 = *8.</summary>
    public byte ConnectionTimeoutMultiplier { get; init; } = 1;

    /// <summary>Priority/Time_tick byte for Forward Open. Default 0x05 (tick=5, priority=0).</summary>
    public byte PriorityTimeTick { get; init; } = 0x05;

    /// <summary>Timeout ticks for Forward Open. Default 156.</summary>
    public byte TimeoutTicks { get; init; } = 156;

    /// <summary>Explicit O→T connection size on wire. If 0, auto-computed from ConsumedDataSize.</summary>
    public ushort OtoTConnectionSize { get; init; }

    /// <summary>Explicit T→O connection size on wire. If 0, auto-computed from ProducedDataSize.</summary>
    public ushort TtoOConnectionSize { get; init; }
}

/// <summary>
/// Builds the Forward Open request data for a CIP Safety connection.
/// Includes the Safety Network Segment (0x50) in the connection path
/// and sets Transport Class 6.
/// </summary>
public static class SafetyForwardOpenBuilder
{
    /// <summary>
    /// Build the Forward Open service data for a safety connection.
    /// Returns (serviceData, pathBytes) ready to send via SendExplicitAsync to Connection Manager.
    /// </summary>
    public static (byte[] ServiceData, byte[] CmPath) Build(SafetyForwardOpenConfig config) =>
        Build(config, (ushort)(Environment.TickCount & 0xFFFF), 0x0001, (uint)Environment.TickCount, 0xA0);

    /// <summary>
    /// Build the Forward Open service data with explicit originator identity and transport direction.
    /// Uses the shortcut path format (20 04 24 xx 2C yy 2C zz) suitable for direct connections.
    /// </summary>
    public static (byte[] ServiceData, byte[] CmPath) Build(
        SafetyForwardOpenConfig config,
        ushort connSerial, ushort origVendor, uint origSerial, byte transportClassTrigger)
    {
        // Connection path: Assembly class + config + connection points + safety segment
        var appPath = new byte[]
        {
            0x20, 0x04,                                 // Class: Assembly
            0x24, (byte)config.ConfigAssembly,          // Instance: config
            0x2C, (byte)config.ConsumedAssembly,        // Connection Point: O→T
            0x2C, (byte)config.ProducedAssembly,        // Connection Point: T→O
        };

        return Build(config, connSerial, origVendor, origSerial, transportClassTrigger,
            routePrefix: Array.Empty<byte>(), appPath: appPath);
    }

    /// <summary>
    /// Build the Forward Open service data with a custom connection path.
    /// Use this for routed connections (e.g., through 1734-ENT to backplane modules).
    /// </summary>
    /// <param name="config">Safety connection configuration.</param>
    /// <param name="connSerial">Connection serial number (unique per connection).</param>
    /// <param name="origVendor">Originator vendor ID.</param>
    /// <param name="origSerial">Originator device serial number.</param>
    /// <param name="transportClassTrigger">Transport class/trigger byte (0xA0=server, 0x20=client).</param>
    /// <param name="routePrefix">Port segment bytes for routing (NOT included in CPCRC).</param>
    /// <param name="appPath">Electronic key + assembly segments (included in CPCRC).</param>
    public static (byte[] ServiceData, byte[] CmPath) Build(
        SafetyForwardOpenConfig config,
        ushort connSerial, ushort origVendor, uint origSerial, byte transportClassTrigger,
        byte[] routePrefix, byte[] appPath)
    {
        // Build safety network segment
        var safetySegment = new SafetyNetworkSegment
        {
            Format = config.Format == SafetyFormat.Extended ? (byte)0x02 : (byte)0x00,
            Sccrc = config.Scid.Sccrc,
            Scts = config.Scid.Sccrc != 0 ? config.Scid.Scts.Data.ToArray() : new byte[6],
            TimeCorrectionEpi = 0,
            TimeCorrectionParams = 0,
            Tunid = config.Tunid,
            Ounid = config.Ounid,
            PingIntervalMultiplier = config.PingIntervalMultiplier,
            TimeCoordMsgMinMultiplier = config.TimeCoordMsgMinMultiplier,
            NetworkTimeExpectationMultiplier = config.NetworkTimeExpectationMultiplier,
            TimeoutMultiplier = config.TimeoutMultiplier,
            MaxConsumerNumber = 1, // Single-cast
            MaxFaultNumber = config.MaxFaultNumber,
            Cpcrc = 0, // Will be computed below
            TimeCorrectionConnectionId = 0xFFFFFFFF,
            InitialTimeStamp = config.InitialTimestamp,
            InitialRolloverValue = config.InitialRolloverValue,
        };

        int segSize = safetySegment.WireSize;
        var safetySegBytes = new byte[segSize];
        safetySegment.Encode(safetySegBytes);

        // Full connection path = routePrefix + appPath + safetySegment
        var connPath = new byte[routePrefix.Length + appPath.Length + safetySegBytes.Length];
        routePrefix.CopyTo(connPath, 0);
        appPath.CopyTo(connPath, routePrefix.Length);
        safetySegBytes.CopyTo(connPath, routePrefix.Length + appPath.Length);

        // Compute connection sizes on wire (including safety framing overhead)
        ushort otConnSize = config.OtoTConnectionSize != 0
            ? config.OtoTConnectionSize
            : (ushort)SafetyFrameCodec.WireSize(config.ConsumedDataSize, config.Format);
        ushort toConnSize = config.TtoOConnectionSize != 0
            ? config.TtoOConnectionSize
            : (ushort)SafetyFrameCodec.WireSize(config.ProducedDataSize, config.Format);

        // Network params: P2P, Fixed, High Priority (safety requires fixed + high priority)
        ushort otParams = (ushort)(0x4400 | (otConnSize & 0x01FF)); // P2P + HighPri + fixed
        ushort toParams = (ushort)(0x4400 | (toConnSize & 0x01FF));

        // For P2P: originator chooses T→O conn ID
        uint toConnId = (uint)(0x10000000 | connSerial);

        // Build Forward Open data first with CPCRC=0, then compute and patch
        var fwdOpenData = new byte[36 + connPath.Length];
        int off = 0;
        fwdOpenData[off++] = config.PriorityTimeTick;
        fwdOpenData[off++] = config.TimeoutTicks;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), 0); off += 4; // OT conn ID (target chooses)
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), toConnId); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), connSerial); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), origVendor); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), origSerial); off += 4;
        fwdOpenData[off++] = config.ConnectionTimeoutMultiplier;
        off += 3; // Reserved
        uint otRpi = config.OtoTRpi != 0 ? config.OtoTRpi : config.Rpi;
        uint toRpi = config.TtoORpi != 0 ? config.TtoORpi : config.Rpi;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), otRpi); off += 4; // OT RPI
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), otParams); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), toRpi); off += 4; // TO RPI
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), toParams); off += 2;
        fwdOpenData[off++] = transportClassTrigger;
        fwdOpenData[off++] = (byte)(connPath.Length / 2);
        connPath.CopyTo(fwdOpenData.AsSpan(off));

        // Compute CPCRC from raw bytes (same method as adapter validation)
        // Per CSS IXSCEmisc.c: CRC-S4 over ConnSerial+OrigVendor | TimeoutMult..PathSize | EKey+AppPath | NSD(50/48B from 0x50)
        int safetyOffInConnPath = routePrefix.Length + appPath.Length; // where 0x50 starts in connPath
        int nsdSize = config.Format == SafetyFormat.Extended ? 50 : 48;

        var crcBuf = new byte[4 + 18 + appPath.Length + nsdSize];
        int ci = 0;
        // ConnSerial(2) + OrigVendor(2) from service data offset 10
        fwdOpenData.AsSpan(10, 4).CopyTo(crcBuf.AsSpan(ci)); ci += 4;
        // TimeoutMult through PathSize from service data offset 18 (18 bytes)
        fwdOpenData.AsSpan(18, 18).CopyTo(crcBuf.AsSpan(ci)); ci += 18;
        // Patch pathSize in CPCRC input: target sees path WITHOUT route prefix
        // PathSize is the last byte of the 18-byte block (at ci - 1)
        crcBuf[ci - 1] = (byte)((appPath.Length + safetySegBytes.Length) / 2);
        // Electronic key + application path (NOT including route prefix)
        appPath.CopyTo(crcBuf.AsSpan(ci)); ci += appPath.Length;
        // Safety segment raw bytes (including 0x50 header), CPCRC field is still 0
        connPath.AsSpan(safetyOffInConnPath, nsdSize).CopyTo(crcBuf.AsSpan(ci)); ci += nsdSize;

        uint cpcrc = SafetyCrc.ComputeS4(crcBuf.AsSpan(0, ci));

        // Patch CPCRC into the connection path within fwdOpenData
        // CPCRC offset within safety segment: 48 (Base) or 50 (Extended) from the 0x50 byte
        int cpcrcAbsOffset = off + safetyOffInConnPath + (config.Format == SafetyFormat.Extended ? 50 : 48);
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(cpcrcAbsOffset), cpcrc);

        var cmPath = new byte[] { 0x20, 0x06, 0x24, 0x01 }; // Connection Manager class 0x06, instance 1
        return (fwdOpenData, cmPath);
    }
}
