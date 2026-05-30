namespace EthernetIPSharp.Safety;

/// <summary>Safety wire format selection.</summary>
public enum SafetyFormat : byte
{
    /// <summary>Base format — separate data, complement, and timestamp sections with CRC-S1/S2/S3.</summary>
    Base = 0,
    /// <summary>Extended format — includes rollover counter, uses CRC-S5. Required for RPI > 100ms over EtherNet/IP.</summary>
    Extended = 1,
}

/// <summary>
/// CIP Safety Mode Byte.
///
/// Bit layout (verified against real 1734 PointIO captures):
///   7: Run_Idle
///   6-5: TBD_2_Bit (reserved, 0)
///   4: N_Run_Idle (complement of bit 7)
///   3: TBD_Bit (reserved, 0)
///   2: N_TBD_Bit (complement of bit 3, always 1)
///   1-0: Ping_Count
///
/// Examples from real device:
///   0x14 = run=0, ping=0 (cold start)
///   0x84 = run=1, ping=0
///   0x85 = run=1, ping=1
///   0x86 = run=1, ping=2
///   0x87 = run=1, ping=3
/// </summary>
public readonly struct ModeByte
{
    private readonly byte _raw;

    public ModeByte(byte raw) => _raw = raw;

    /// <summary>True if the producer is in Run state.</summary>
    public bool RunIdle => (_raw & 0x80) != 0;

    /// <summary>Ping count (2 bits, values 0-3). Incremented by producer to trigger time coordination.</summary>
    public byte PingCount => (byte)(_raw & 0x03);

    /// <summary>The raw byte value.</summary>
    public byte Value => _raw;

    /// <summary>Bits used in actual/complement data CRC calculation: ModeByte AND 0xE0.</summary>
    public byte DataCrcMask => (byte)(_raw & 0xE0);

    /// <summary>Bits used in complement data CRC (base format): (ModeByte XOR 0xFF) AND 0xE0.</summary>
    public byte ComplementDataCrcMask => (byte)((_raw ^ 0xFF) & 0xE0);

    /// <summary>Bits used in timestamp CRC calculation: ModeByte AND 0x1F.</summary>
    public byte TimestampCrcMask => (byte)(_raw & 0x1F);

    /// <summary>Build a mode byte with auto-computed redundant bits.</summary>
    public static ModeByte Create(bool runIdle, byte pingCount)
    {
        byte raw = 0;
        if (runIdle) raw |= 0x80;               // bit 7: Run_Idle
        raw |= (byte)(pingCount & 0x03);         // bits 1-0: Ping_Count
        // TBD_2_Bit (bits 6-5) = 0, TBD_Bit (bit 3) = 0
        // Compute redundant complement bits
        raw = ComputeRedundantBits(raw);
        return new ModeByte(raw);
    }

    /// <summary>
    /// Compute redundant bits (complement/copy).
    /// Bit 4 = NOT(bit 7), bit 2 = NOT(bit 3).
    /// </summary>
    public static byte ComputeRedundantBits(byte raw)
    {
        // N_Run_Idle (bit 4) = complement of Run_Idle (bit 7)
        if ((raw & 0x80) == 0)
            raw |= 0x10;
        else
            raw = (byte)(raw & ~0x10);

        // N_TBD_Bit (bit 2) = complement of TBD_Bit (bit 3)
        if ((raw & 0x08) == 0)
            raw |= 0x04;
        else
            raw = (byte)(raw & ~0x04);

        return raw;
    }

    /// <summary>Validate that redundant bits are consistent. Returns true if valid.</summary>
    public bool Validate()
    {
        bool runIdle = (_raw & 0x80) != 0;
        bool nRunIdle = (_raw & 0x10) != 0;
        if (runIdle == nRunIdle) return false; // must be complement

        bool tbdBit = (_raw & 0x08) != 0;
        bool nTbdBit = (_raw & 0x04) != 0;
        if (tbdBit == nTbdBit) return false; // must be complement

        return true;
    }
}

/// <summary>Safety Network Number — 6-byte unique identifier for a safety network.</summary>
public readonly struct SafetyNetworkNumber
{
    public static readonly SafetyNetworkNumber Zero = new(new byte[6]);

    private readonly byte[] _data;

    public SafetyNetworkNumber(byte[] data)
    {
        if (data.Length != 6)
            throw new ArgumentException("SNN must be exactly 6 bytes");
        _data = data;
    }

    public ReadOnlySpan<byte> Data => _data ?? Array.Empty<byte>();

    public void CopyTo(Span<byte> dst) => (_data ?? new byte[6]).CopyTo(dst);
}

/// <summary>
/// Safety Configuration Identifier (SCID).
/// Composed of SCCRC (4 bytes) + SCTS (6 bytes) = 10 bytes total.
/// </summary>
public readonly struct SafetyConfigurationId
{
    /// <summary>Safety Configuration CRC — CRC-S4 over device configuration.</summary>
    public uint Sccrc { get; init; }

    /// <summary>Safety Configuration Time Stamp — 6-byte date/time when config was applied.</summary>
    public SafetyNetworkNumber Scts { get; init; }

    /// <summary>Total encoded size.</summary>
    public const int Size = 10;

    public void CopyTo(Span<byte> dst)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(dst, Sccrc);
        Scts.CopyTo(dst.Slice(4));
    }

    public static SafetyConfigurationId Parse(ReadOnlySpan<byte> data)
    {
        return new SafetyConfigurationId
        {
            Sccrc = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(data),
            Scts = new SafetyNetworkNumber(data.Slice(4, 6).ToArray()),
        };
    }
}

/// <summary>Unique Network Identifier — SNN(6) + NodeAddress(4) = 10 bytes.</summary>
public readonly struct UniqueNetworkId
{
    public SafetyNetworkNumber Snn { get; init; }
    public uint NodeAddress { get; init; }

    public const int Size = 10;

    public void CopyTo(Span<byte> dst)
    {
        Snn.CopyTo(dst);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(dst.Slice(6), NodeAddress);
    }

    public static UniqueNetworkId Parse(ReadOnlySpan<byte> data)
    {
        return new UniqueNetworkId
        {
            Snn = new SafetyNetworkNumber(data.Slice(0, 6).ToArray()),
            NodeAddress = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(6)),
        };
    }
}
