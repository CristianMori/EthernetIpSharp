using System.Buffers.Binary;

namespace EthernetIPSharp.Safety;

/// <summary>
/// Safety Network Segment (0x50) parser/encoder for Forward Open connection paths.
///
/// Segment wire format:
///   [0x50] [DataLengthWords] [Format] [SegmentData...]
///
/// Three formats:
///   0x00 = Target Format (56 bytes total, 27 words data)
///   0x01 = Router Format (14 bytes total, 6 words data)
///   0x02 = Extended Format (62 bytes total, 30 words data) — adds Max_Fault_Number,
///          Initial_Time_Stamp, Initial_Rollover_Value vs Target Format
/// </summary>
public readonly struct SafetyNetworkSegment
{
    /// <summary>Network segment type byte for safety.</summary>
    public const byte SegmentType = 0x50;

    /// <summary>Safety segment format: 0=Target, 1=Router, 2=Extended.</summary>
    public byte Format { get; init; }

    /// <summary>Safety Configuration CRC (SCCRC) — CRC-S4 over device configuration.</summary>
    public uint Sccrc { get; init; }

    /// <summary>Safety Configuration Time Stamp (SCTS) — 6 bytes.</summary>
    public byte[] Scts { get; init; }

    /// <summary>Time Correction EPI (0 if not used).</summary>
    public uint TimeCorrectionEpi { get; init; }

    /// <summary>Time Correction Network Connection Parameters (0 if not used).</summary>
    public ushort TimeCorrectionParams { get; init; }

    /// <summary>Target Unique Network Identifier (TUNID) — SNN(6) + NodeAddress(4).</summary>
    public UniqueNetworkId Tunid { get; init; }

    /// <summary>Originator Unique Network Identifier (OUNID) — SNN(6) + NodeAddress(4).</summary>
    public UniqueNetworkId Ounid { get; init; }

    /// <summary>Ping_Interval_EPI_Multiplier.</summary>
    public ushort PingIntervalMultiplier { get; init; }

    /// <summary>Time_Coord_Msg_Min_Multiplier.</summary>
    public ushort TimeCoordMsgMinMultiplier { get; init; }

    /// <summary>Network_Time_Expectation_Multiplier.</summary>
    public ushort NetworkTimeExpectationMultiplier { get; init; }

    /// <summary>Timeout_Multiplier (1-4).</summary>
    public byte TimeoutMultiplier { get; init; }

    /// <summary>Max_Consumer_Number (1=single-cast, 2-15=multicast).</summary>
    public byte MaxConsumerNumber { get; init; }

    /// <summary>Connection Parameters CRC (CPCRC) — CRC-S4 over Forward Open parameters.</summary>
    public uint Cpcrc { get; init; }

    /// <summary>Time Correction Connection ID (0xFFFFFFFF if not used).</summary>
    public uint TimeCorrectionConnectionId { get; init; }

    // --- Extended Format (0x02) additional fields ---

    /// <summary>Max_Fault_Number (Extended Format only). Valid range 1-15.</summary>
    public ushort MaxFaultNumber { get; init; }

    /// <summary>Initial_Time_Stamp (Extended Format only). Starting timestamp value.</summary>
    public ushort InitialTimeStamp { get; init; }

    /// <summary>Initial_Rollover_Value (Extended Format only). Starting rollover count.</summary>
    public ushort InitialRolloverValue { get; init; }

    /// <summary>Total segment size on wire including the 0x50 type byte and length byte.</summary>
    public int WireSize => Format switch
    {
        0x00 => 56, // Target format: 2 header + 54 data (27 words)
        0x01 => 14, // Router format: 2 header + 12 data (6 words)
        0x02 => 62, // Extended format: 2 header + 60 data (30 words)
        _ => 2,
    };

    /// <summary>
    /// Parse a Safety Network Segment from connection path data.
    /// The input should start at the 0x50 byte.
    /// Returns the parsed segment and number of bytes consumed.
    /// </summary>
    public static (SafetyNetworkSegment Segment, int BytesConsumed) Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 3 || data[0] != SegmentType)
            throw new ArgumentException("Not a safety network segment");

        byte dataLenWords = data[1];
        int dataLenBytes = dataLenWords * 2;
        byte format = data[2];

        int totalSize = 2 + dataLenBytes; // type(1) + length(1) + data

        if (data.Length < totalSize)
            throw new ArgumentException($"Safety segment requires {totalSize} bytes, got {data.Length}");

        if (format == 0x01) // Router format
        {
            return (new SafetyNetworkSegment
            {
                Format = 0x01,
                TimeCorrectionConnectionId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4)),
                TimeCorrectionEpi = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8)),
                TimeCorrectionParams = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(12)),
            }, totalSize);
        }

        // Target format (0x00) and Extended format (0x02) share the same base layout
        int off = 3; // skip type + length + format
        off++;       // reserved pad

        uint sccrc = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(off)); off += 4;
        var scts = data.Slice(off, 6).ToArray(); off += 6;
        uint tcEpi = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(off)); off += 4;
        ushort tcParams = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(off)); off += 2;
        var tunid = UniqueNetworkId.Parse(data.Slice(off)); off += UniqueNetworkId.Size;
        var ounid = UniqueNetworkId.Parse(data.Slice(off)); off += UniqueNetworkId.Size;
        ushort pingMult = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(off)); off += 2;
        ushort tcMsgMult = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(off)); off += 2;
        ushort nteMult = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(off)); off += 2;
        byte timeoutMult = data[off++];
        byte maxConsumer = data[off++];

        // Extended Format (0x02) has Max_Fault_Number here before CPCRC
        ushort maxFaultNum = 0;
        if (format == 0x02)
        {
            maxFaultNum = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(off)); off += 2;
        }

        uint cpcrc = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(off)); off += 4;
        uint tcConnId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(off)); off += 4;

        // Extended Format (0x02) has Initial_Time_Stamp and Initial_Rollover_Value after TC conn ID
        ushort initTs = 0;
        ushort initRollover = 0;
        if (format == 0x02)
        {
            initTs = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(off)); off += 2;
            initRollover = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(off)); off += 2;
        }

        return (new SafetyNetworkSegment
        {
            Format = format,
            Sccrc = sccrc,
            Scts = scts,
            TimeCorrectionEpi = tcEpi,
            TimeCorrectionParams = tcParams,
            Tunid = tunid,
            Ounid = ounid,
            PingIntervalMultiplier = pingMult,
            TimeCoordMsgMinMultiplier = tcMsgMult,
            NetworkTimeExpectationMultiplier = nteMult,
            TimeoutMultiplier = timeoutMult,
            MaxConsumerNumber = maxConsumer,
            MaxFaultNumber = maxFaultNum,
            Cpcrc = cpcrc,
            TimeCorrectionConnectionId = tcConnId,
            InitialTimeStamp = initTs,
            InitialRolloverValue = initRollover,
        }, totalSize);
    }

    /// <summary>
    /// Encode a Target or Extended format safety segment to wire format.
    /// Returns the number of bytes written (56 for Target, 62 for Extended).
    /// </summary>
    public int Encode(Span<byte> output)
    {
        bool isExtended = Format == 0x02;
        byte dataLenWords = isExtended ? (byte)0x1E : (byte)0x1B; // 30 or 27 words

        int off = 0;
        output[off++] = SegmentType;    // 0x50
        output[off++] = dataLenWords;

        output[off++] = Format;
        output[off++] = 0;             // reserved pad

        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(off), Sccrc); off += 4;
        (Scts ?? new byte[6]).CopyTo(output.Slice(off)); off += 6;
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(off), TimeCorrectionEpi); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), TimeCorrectionParams); off += 2;
        Tunid.CopyTo(output.Slice(off)); off += UniqueNetworkId.Size;
        Ounid.CopyTo(output.Slice(off)); off += UniqueNetworkId.Size;
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), PingIntervalMultiplier); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), TimeCoordMsgMinMultiplier); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), NetworkTimeExpectationMultiplier); off += 2;
        output[off++] = TimeoutMultiplier;
        output[off++] = MaxConsumerNumber;

        if (isExtended)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), MaxFaultNumber); off += 2;
        }

        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(off), Cpcrc); off += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(off), TimeCorrectionConnectionId); off += 4;

        if (isExtended)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), InitialTimeStamp); off += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), InitialRolloverValue); off += 2;
        }

        return off;
    }
}
