using System.Buffers.Binary;

namespace EthernetIPSharp.Connections;

/// <summary>
/// Parsed Forward Open / Large Forward Open request parameters (Vol1 Table 3-5.17).
/// Immutable struct — parse once, read many.
/// </summary>
public readonly struct ForwardOpenRequest
{
    /// <summary>Priority and time tick for unconnected request timeout (Vol1 §3-5.4.1.2.1).</summary>
    public byte PriorityTimeTick { get; init; }

    /// <summary>Number of ticks for unconnected request timeout.</summary>
    public byte TimeoutTicks { get; init; }

    /// <summary>O→T Network Connection ID proposed by the originator (target may override for P2P).</summary>
    public uint OtoTConnectionId { get; init; }

    /// <summary>T→O Network Connection ID chosen by the originator (for P2P T→O, originator is consumer).</summary>
    public uint TtoOConnectionId { get; init; }

    /// <summary>Connection serial number — unique per originator, part of the connection triad.</summary>
    public ushort ConnectionSerialNumber { get; init; }

    /// <summary>Vendor ID of the originator device.</summary>
    public ushort OriginatorVendorId { get; init; }

    /// <summary>Serial number of the originator device.</summary>
    public uint OriginatorSerialNumber { get; init; }

    /// <summary>Connection timeout multiplier code (0=x4, 1=x8, ... 7=x512).</summary>
    public byte ConnectionTimeoutMultiplier { get; init; }

    /// <summary>O→T Requested Packet Interval in microseconds.</summary>
    public uint OtoTRpi { get; init; }

    /// <summary>O→T network connection parameters (size, type, priority).</summary>
    public NetworkConnectionParams OtoTParams { get; init; }

    /// <summary>T→O Requested Packet Interval in microseconds.</summary>
    public uint TtoORpi { get; init; }

    /// <summary>T→O network connection parameters (size, type, priority).</summary>
    public NetworkConnectionParams TtoOParams { get; init; }

    /// <summary>
    /// Transport class and trigger byte.
    /// Bits 0-3: transport class (0-3). Bits 4-6: trigger type. Bit 7: direction.
    /// </summary>
    public byte TransportClassTrigger { get; init; }

    /// <summary>Size of the connection path in 16-bit words.</summary>
    public byte ConnectionPathSizeWords { get; init; }

    /// <summary>Raw connection path bytes (application path with optional electronic key, routing segments).</summary>
    public ReadOnlyMemory<byte> ConnectionPath { get; init; }

    /// <summary>Transport class extracted from TransportClassTrigger (bits 0-3).</summary>
    public TransportClass TransportClass => (TransportClass)(TransportClassTrigger & 0x03);

    /// <summary>True if this was parsed from a Large Forward Open (0x5B) with 32-bit network params.</summary>
    public bool IsLargeForwardOpen { get; init; }

    /// <summary>Minimum data length for a standard Forward Open (excluding connection path).</summary>
    private const int MinForwardOpenSize = 36; // 2+4+4+2+2+4+1+3+4+2+4+2+1+1 = 36

    /// <summary>Minimum data length for a Large Forward Open (excluding connection path).</summary>
    private const int MinLargeForwardOpenSize = 40; // same but network params are 4 bytes each instead of 2

    /// <summary>
    /// Parse a Forward Open or Large Forward Open request from the service request data.
    /// Throws ArgumentException if the data is too short.
    /// </summary>
    public static ForwardOpenRequest Parse(ReadOnlySpan<byte> data, bool isLarge = false)
    {
        int minSize = isLarge ? MinLargeForwardOpenSize : MinForwardOpenSize;
        if (data.Length < minSize)
            throw new ArgumentException(
                $"Forward Open requires at least {minSize} bytes, got {data.Length}");

        int offset = 0;

        // Common fields (same layout for both Forward Open and Large Forward Open)
        byte priorityTimeTick = data[offset++];
        byte timeoutTicks = data[offset++];
        uint otConnId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
        uint toConnId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
        ushort connSerial = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
        ushort origVendor = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
        uint origSerial = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
        byte timeoutMult = data[offset++];
        offset += 3; // 3 reserved bytes

        // O→T RPI + network params (size differs for Large)
        uint otRpi = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;

        NetworkConnectionParams otParams;
        NetworkConnectionParams toParams;
        uint toRpi;

        if (isLarge)
        {
            uint otParamsRaw = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
            otParams = NetworkConnectionParams.ParseLarge(otParamsRaw);
            toRpi = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
            uint toParamsRaw = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
            toParams = NetworkConnectionParams.ParseLarge(toParamsRaw);
        }
        else
        {
            ushort otParamsRaw = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
            otParams = NetworkConnectionParams.Parse(otParamsRaw);
            toRpi = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
            ushort toParamsRaw = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
            toParams = NetworkConnectionParams.Parse(toParamsRaw);
        }

        // Transport class/trigger + connection path
        byte transportClassTrigger = data[offset++];
        byte pathSize = data[offset++];
        int pathBytes = pathSize * 2;

        if (offset + pathBytes > data.Length)
            throw new ArgumentException(
                $"Connection path requires {pathBytes} bytes at offset {offset}, but data has {data.Length}");

        var path = data.Slice(offset, pathBytes).ToArray();

        return new ForwardOpenRequest
        {
            PriorityTimeTick = priorityTimeTick,
            TimeoutTicks = timeoutTicks,
            OtoTConnectionId = otConnId,
            TtoOConnectionId = toConnId,
            ConnectionSerialNumber = connSerial,
            OriginatorVendorId = origVendor,
            OriginatorSerialNumber = origSerial,
            ConnectionTimeoutMultiplier = timeoutMult,
            OtoTRpi = otRpi,
            OtoTParams = otParams,
            TtoORpi = toRpi,
            TtoOParams = toParams,
            TransportClassTrigger = transportClassTrigger,
            ConnectionPathSizeWords = pathSize,
            ConnectionPath = path,
            IsLargeForwardOpen = isLarge,
        };
    }
}

/// <summary>
/// Parsed network connection parameters from Forward Open.
///
/// 16-bit layout (Vol1 Table 3-5.8):
///   Bit 15: redundant owner
///   Bits 14-13: connection type (0=Null, 1=Multicast, 2=P2P)
///   Bits 12-10: priority
///   Bit 9: fixed(0) / variable(1)
///   Bits 8-0: connection size in bytes
///
/// 32-bit layout (Large Forward Open, Vol1 Table 3-5.9):
///   Bit 31: redundant owner
///   Bits 30-29: connection type
///   Bits 28-26: priority
///   Bit 25: fixed/variable
///   Bits 15-0: connection size in bytes
/// </summary>
public readonly struct NetworkConnectionParams
{
    /// <summary>True if redundant owner is allowed for this connection.</summary>
    public bool RedundantOwner { get; init; }

    /// <summary>Connection type: 0=Null, 1=Multicast, 2=Point-to-Point.</summary>
    public byte ConnectionType { get; init; }

    /// <summary>Priority level: 0=Low, 1=High, 2=Scheduled, 3=Urgent.</summary>
    public byte Priority { get; init; }

    /// <summary>True if connection size is variable (up to max), false if fixed.</summary>
    public bool IsVariable { get; init; }

    /// <summary>Maximum connection size in bytes (includes CIP sequence count for Class 1).</summary>
    public ushort ConnectionSize { get; init; }

    /// <summary>True if connection type is Null (no network connection opened).</summary>
    public bool IsNull => ConnectionType == 0;

    /// <summary>Parse from a 16-bit Forward Open network connection parameter word.</summary>
    public static NetworkConnectionParams Parse(ushort raw) => new()
    {
        RedundantOwner = (raw & 0x8000) != 0,
        ConnectionType = (byte)((raw >> 13) & 0x03),
        Priority = (byte)((raw >> 10) & 0x03),
        IsVariable = (raw & 0x0200) != 0,
        ConnectionSize = (ushort)(raw & 0x01FF),
    };

    /// <summary>Parse from a 32-bit Large Forward Open network connection parameter dword.</summary>
    public static NetworkConnectionParams ParseLarge(uint raw) => new()
    {
        RedundantOwner = (raw & 0x80000000) != 0,
        ConnectionType = (byte)((raw >> 29) & 0x03),
        Priority = (byte)((raw >> 26) & 0x03),
        IsVariable = (raw & 0x02000000) != 0,
        ConnectionSize = (ushort)(raw & 0xFFFF),
    };
}
