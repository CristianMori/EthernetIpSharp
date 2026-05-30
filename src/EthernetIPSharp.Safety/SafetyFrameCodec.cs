using System.Buffers.Binary;

namespace EthernetIPSharp.Safety;

/// <summary>
/// Encodes and decodes CIP Safety wire format frames.
///
/// Four variants supported:
///   Base Short  (1-2 byte data):  [Data][Mode][CRC-S1][CRC-S2] | [Timestamp][CRC-S1]
///   Base Long   (3-250 byte data):[Data][Mode][CRC-S3][~Data][CRC-S3] | [Timestamp][CRC-S1]
///   Extended Short (1-2 byte):    [Data][Mode][S5_0(2)][S5_1(1)][Timestamp(2)][S5_2(1)]
///   Extended Long  (3-250 byte):  [Data][Mode][CRC-S3][~Data][S5_0(2)][S5_1(1)][Timestamp(2)][S5_2(1)]
/// </summary>
public static class SafetyFrameCodec
{
    /// <summary>Compute the total wire size for a safety frame given the actual data length.</summary>
    public static int WireSize(int dataLength, SafetyFormat format)
    {
        bool isShort = dataLength <= 2;

        return (format, isShort) switch
        {
            // Base Short:    data + mode(1) + S1(1) + S2(1) + ts(2) + tsS1(1) = data + 6
            (SafetyFormat.Base, true) => dataLength + 6,
            // Base Long:     data + mode(1) + S3(2) + ~data + S3(2) + ts(2) + tsS1(1) = 2*data + 8
            (SafetyFormat.Base, false) => 2 * dataLength + 8,
            // Extended Short: data + mode(1) + S5_lo(2) + ts(2) + S5_hi(1) = data + 6
            // Per CSS: CSOS_k_IO_MSGLEN_SHORT_OVHD = 6 for BOTH Base and Extended!
            (SafetyFormat.Extended, true) => dataLength + 6,
            // Extended Long:  data + mode(1) + S3(2) + ~data + S5_lo(2) + ts(2) + S5_hi(1) = 2*data + 8
            (SafetyFormat.Extended, false) => 2 * dataLength + 8,
            _ => throw new ArgumentException("Invalid format"),
        };
    }

    /// <summary>
    /// Encode a safety data frame.
    /// Returns the number of bytes written to output.
    /// </summary>
    public static int Encode(Span<byte> output, ReadOnlySpan<byte> actualData,
        SafetyFormat format, ModeByte mode, ushort timestamp,
        byte pidSeedS1, ushort pidSeedS3, uint pidSeedS5,
        ushort rolloverCount = 0)
    {
        bool isShort = actualData.Length <= 2;

        if (format == SafetyFormat.Base)
            return isShort
                ? EncodeBaseShort(output, actualData, mode, timestamp, pidSeedS1)
                : EncodeBaseLong(output, actualData, mode, timestamp, pidSeedS1, pidSeedS3);
        else
            return isShort
                ? EncodeExtendedShort(output, actualData, mode, timestamp, pidSeedS5, rolloverCount)
                : EncodeExtendedLong(output, actualData, mode, timestamp, pidSeedS3, pidSeedS5, rolloverCount);
    }

    /// <summary>
    /// Extract just the wire timestamp from a safety data frame (no CRC check).
    /// Needed by the consumer to track the originator's rolloverCount BEFORE
    /// the CRC validation step (which depends on rolloverCount).
    /// </summary>
    public static ushort ExtractTimestamp(ReadOnlySpan<byte> input, int actualDataLength, SafetyFormat format)
    {
        bool isShort = actualDataLength <= 2;
        // ts position per layout:
        //   Base Short:     data + mode + S1 + S2 + [ts(2)] + tsS1
        //   Extended Short: data + mode + S5_lo(2) + [ts(2)] + S5_hi
        //   Base Long:      data + mode + S3(2) + ~data + S3(2) + [ts(2)] + tsS1
        //   Extended Long:  data + mode + S3(2) + ~data + S5_0(2) + S5_1 + [ts(2)] + S5_2
        int offset = isShort
            ? actualDataLength + 3
            : (format == SafetyFormat.Base ? 2 * actualDataLength + 5 : 2 * actualDataLength + 6);
        if (offset + 2 > input.Length) return 0;
        return BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(offset));
    }

    /// <summary>
    /// Decode a safety data frame. Returns the decoded result with CRC validation status.
    /// </summary>
    public static SafetyDecodeResult Decode(ReadOnlySpan<byte> input, int actualDataLength,
        SafetyFormat format, byte pidSeedS1, ushort pidSeedS3, uint pidSeedS5,
        ushort rolloverCount = 0)
    {
        bool isShort = actualDataLength <= 2;

        if (format == SafetyFormat.Base)
            return isShort
                ? DecodeBaseShort(input, actualDataLength, pidSeedS1)
                : DecodeBaseLong(input, actualDataLength, pidSeedS1, pidSeedS3);
        else
            return isShort
                ? DecodeExtendedShort(input, actualDataLength, pidSeedS5, rolloverCount)
                : DecodeExtendedLong(input, actualDataLength, pidSeedS3, pidSeedS5, rolloverCount);
    }

    // ==================== Base Format Short (1-2 bytes) ====================

    private static int EncodeBaseShort(Span<byte> output, ReadOnlySpan<byte> data,
        ModeByte mode, ushort timestamp, byte pidSeedS1)
    {
        int off = 0;

        // Data section: [ActualData] [ModeByte] [CRC-S1] [CRC-S2]
        data.CopyTo(output.Slice(off)); off += data.Length;
        output[off++] = mode.Value;

        // Actual CRC-S1: seed → (mode & 0xE0) → actualData
        byte aCrc = SafetyCrc.ComputeS1([mode.DataCrcMask], pidSeedS1);
        aCrc = SafetyCrc.ComputeS1(data, aCrc);
        output[off++] = aCrc;

        // Complement CRC-S2: seed(S1!) → ((mode^0xFF) & 0xE0) → (data^0xFF)
        byte cCrc = SafetyCrc.ComputeS2([mode.ComplementDataCrcMask], pidSeedS1);
        Span<byte> compData = stackalloc byte[data.Length];
        for (int i = 0; i < data.Length; i++) compData[i] = (byte)(data[i] ^ 0xFF);
        cCrc = SafetyCrc.ComputeS2(compData, cCrc);
        output[off++] = cCrc;

        // Timestamp section: [Timestamp(2)] [CRC-S1]
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), timestamp); off += 2;

        byte tsCrc = SafetyCrc.ComputeS1([mode.TimestampCrcMask], pidSeedS1);
        Span<byte> tsBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(tsBytes, timestamp);
        tsCrc = SafetyCrc.ComputeS1(tsBytes, tsCrc);
        output[off++] = tsCrc;

        return off;
    }

    private static SafetyDecodeResult DecodeBaseShort(ReadOnlySpan<byte> input, int dataLen, byte pidSeedS1)
    {
        int expectedSize = dataLen + 6;
        if (input.Length < expectedSize)
            return SafetyDecodeResult.Error("Input too short for base short frame");

        int off = 0;
        var data = input.Slice(off, dataLen).ToArray(); off += dataLen;
        var mode = new ModeByte(input[off++]);
        byte wireCrcA = input[off++];
        byte wireCrcC = input[off++];
        ushort timestamp = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(off)); off += 2;
        byte wireCrcTs = input[off++];

        // Validate actual CRC
        byte aCrc = SafetyCrc.ComputeS1([mode.DataCrcMask], pidSeedS1);
        aCrc = SafetyCrc.ComputeS1(data, aCrc);
        if (aCrc != wireCrcA)
            return SafetyDecodeResult.Error("Actual data CRC-S1 mismatch");

        // Validate complement CRC
        byte cCrc = SafetyCrc.ComputeS2([mode.ComplementDataCrcMask], pidSeedS1);
        var compData = new byte[dataLen];
        for (int i = 0; i < dataLen; i++) compData[i] = (byte)(data[i] ^ 0xFF);
        cCrc = SafetyCrc.ComputeS2(compData, cCrc);
        if (cCrc != wireCrcC)
            return SafetyDecodeResult.Error("Complement data CRC-S2 mismatch");

        // Validate timestamp CRC
        byte tsCrc = SafetyCrc.ComputeS1([mode.TimestampCrcMask], pidSeedS1);
        Span<byte> tsBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(tsBytes, timestamp);
        tsCrc = SafetyCrc.ComputeS1(tsBytes, tsCrc);
        if (tsCrc != wireCrcTs)
            return SafetyDecodeResult.Error("Timestamp CRC-S1 mismatch");

        return new SafetyDecodeResult(data, mode, timestamp, true, null);
    }

    // ==================== Base Format Long (3-250 bytes) ====================

    private static int EncodeBaseLong(Span<byte> output, ReadOnlySpan<byte> data,
        ModeByte mode, ushort timestamp, byte pidSeedS1, ushort pidSeedS3)
    {
        int off = 0;

        // Data section: [ActualData] [ModeByte] [CRC-S3(2)] [ComplementData] [CRC-S3(2)]
        data.CopyTo(output.Slice(off)); off += data.Length;
        output[off++] = mode.Value;

        // Actual CRC-S3: seed → (mode & 0xE0) → actualData
        ushort aCrc = SafetyCrc.ComputeS3(mode.DataCrcMask, pidSeedS3);
        aCrc = SafetyCrc.ComputeS3(data, aCrc);
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), aCrc); off += 2;

        // Complement data
        for (int i = 0; i < data.Length; i++)
            output[off + i] = (byte)(data[i] ^ 0xFF);
        var compSlice = output.Slice(off, data.Length);
        off += data.Length;

        // Complement CRC-S3: seed → ((mode^0xFF) & 0xE0) → complementData
        ushort cCrc = SafetyCrc.ComputeS3(mode.ComplementDataCrcMask, pidSeedS3);
        cCrc = SafetyCrc.ComputeS3(compSlice, cCrc);
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), cCrc); off += 2;

        // Timestamp section: [Timestamp(2)] [CRC-S1]
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), timestamp); off += 2;

        byte tsCrc = SafetyCrc.ComputeS1([mode.TimestampCrcMask], pidSeedS1);
        Span<byte> tsBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(tsBytes, timestamp);
        tsCrc = SafetyCrc.ComputeS1(tsBytes, tsCrc);
        output[off++] = tsCrc;

        return off;
    }

    private static SafetyDecodeResult DecodeBaseLong(ReadOnlySpan<byte> input, int dataLen,
        byte pidSeedS1, ushort pidSeedS3)
    {
        int expectedSize = 2 * dataLen + 8;
        if (input.Length < expectedSize)
            return SafetyDecodeResult.Error("Input too short for base long frame");

        int off = 0;
        var data = input.Slice(off, dataLen).ToArray(); off += dataLen;
        var mode = new ModeByte(input[off++]);
        ushort wireCrcA = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(off)); off += 2;
        var compData = input.Slice(off, dataLen).ToArray(); off += dataLen;
        ushort wireCrcC = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(off)); off += 2;
        ushort timestamp = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(off)); off += 2;
        byte wireCrcTs = input[off++];

        // Validate actual vs complement data
        for (int i = 0; i < dataLen; i++)
        {
            if ((byte)(data[i] ^ 0xFF) != compData[i])
                return SafetyDecodeResult.Error("Actual vs complement data mismatch");
        }

        // Validate actual CRC-S3
        ushort aCrc = SafetyCrc.ComputeS3(mode.DataCrcMask, pidSeedS3);
        aCrc = SafetyCrc.ComputeS3(data, aCrc);
        if (aCrc != wireCrcA)
            return SafetyDecodeResult.Error("Actual data CRC-S3 mismatch");

        // Validate complement CRC-S3
        ushort cCrc = SafetyCrc.ComputeS3(mode.ComplementDataCrcMask, pidSeedS3);
        cCrc = SafetyCrc.ComputeS3(compData, cCrc);
        if (cCrc != wireCrcC)
            return SafetyDecodeResult.Error("Complement data CRC-S3 mismatch");

        // Validate timestamp CRC-S1
        byte tsCrc = SafetyCrc.ComputeS1([mode.TimestampCrcMask], pidSeedS1);
        Span<byte> tsBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(tsBytes, timestamp);
        tsCrc = SafetyCrc.ComputeS1(tsBytes, tsCrc);
        if (tsCrc != wireCrcTs)
            return SafetyDecodeResult.Error("Timestamp CRC-S1 mismatch");

        return new SafetyDecodeResult(data, mode, timestamp, true, null);
    }

    // ==================== Extended Format Short (1-2 bytes) ====================

    private static int EncodeExtendedShort(Span<byte> output, ReadOnlySpan<byte> data,
        ModeByte mode, ushort timestamp, uint pidSeedS5, ushort rolloverCount)
    {
        int off = 0;

        // Per CSS IXSFAext.c IXSFA_EfsMsgRead:
        // Wire layout: [Data(1-2)] [Mode(1)] [S5_lo(2)] [Timestamp(2)] [S5_hi(1)]
        // Total = data + 6 bytes overhead (same as Base format!)
        data.CopyTo(output.Slice(off)); off += data.Length;
        output[off++] = mode.Value;

        // CRC-S5 over: PID + rollover → (mode & 0xE0) → data → timestamp
        uint rcSeed = SafetyCrc.PidRolloverSeedS5(rolloverCount, pidSeedS5);

        var crcInput = new byte[1 + data.Length + 2];
        crcInput[0] = mode.DataCrcMask;
        data.CopyTo(crcInput.AsSpan(1));
        BinaryPrimitives.WriteUInt16LittleEndian(crcInput.AsSpan(1 + data.Length), timestamp);

        uint s5 = SafetyCrc.ComputeS5Raw(crcInput, rcSeed);

        // Split 24-bit CRC-S5: low 16 bits before timestamp, high 8 bits after
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), (ushort)(s5 & 0xFFFF)); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), timestamp); off += 2;
        output[off++] = (byte)((s5 >> 16) & 0xFF);

        return off;
    }

    private static SafetyDecodeResult DecodeExtendedShort(ReadOnlySpan<byte> input, int dataLen,
        uint pidSeedS5, ushort rolloverCount)
    {
        // Wire layout: [Data(1-2)] [Mode(1)] [S5_lo(2)] [Timestamp(2)] [S5_hi(1)]
        int expectedSize = dataLen + 6;
        if (input.Length < expectedSize)
            return SafetyDecodeResult.Error("Input too short for extended short frame");

        int off = 0;
        var data = input.Slice(off, dataLen).ToArray(); off += dataLen;
        var mode = new ModeByte(input[off++]);
        ushort s5Lo = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(off)); off += 2;
        ushort timestamp = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(off)); off += 2;
        byte s5Hi = input[off++];

        // Reconstruct and validate CRC-S5
        uint rcSeed = SafetyCrc.PidRolloverSeedS5(rolloverCount, pidSeedS5);
        var crcInput = new byte[1 + dataLen + 2];
        crcInput[0] = mode.DataCrcMask;
        data.CopyTo(crcInput.AsSpan(1));
        BinaryPrimitives.WriteUInt16LittleEndian(crcInput.AsSpan(1 + dataLen), timestamp);
        uint expectedS5 = SafetyCrc.ComputeS5Raw(crcInput, rcSeed);

        uint wireS5 = (uint)(s5Lo | ((uint)s5Hi << 16));
        if (wireS5 != (expectedS5 & 0x00FFFFFF))
            return SafetyDecodeResult.Error("Extended short CRC-S5 mismatch");

        return new SafetyDecodeResult(data, mode, timestamp, true, null);
    }

    // ==================== Extended Format Long (3-250 bytes) ====================

    private static int EncodeExtendedLong(Span<byte> output, ReadOnlySpan<byte> data,
        ModeByte mode, ushort timestamp, ushort pidSeedS3, uint pidSeedS5, ushort rolloverCount)
    {
        int off = 0;

        // [Data] [Mode] [CRC-S3(2)] [~Data] [S5_0(2)] [S5_1(1)] [Timestamp(2)] [S5_2(1)]
        data.CopyTo(output.Slice(off)); off += data.Length;
        output[off++] = mode.Value;

        // Actual CRC-S3: PID+rollover seed → (mode & 0xE0) → actualData
        ushort rcSeedS3 = SafetyCrc.PidRolloverSeedS3(rolloverCount, pidSeedS3);
        ushort aCrc = SafetyCrc.ComputeS3(mode.DataCrcMask, rcSeedS3);
        aCrc = SafetyCrc.ComputeS3(data, aCrc);
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), aCrc); off += 2;

        // Complement data
        for (int i = 0; i < data.Length; i++)
            output[off + i] = (byte)(data[i] ^ 0xFF);
        var compSlice = output.Slice(off, data.Length);
        off += data.Length;

        // Complement CRC-S5: PID+rollover seed → (mode & 0x1F) → complementData → timestamp
        uint rcSeedS5 = SafetyCrc.PidRolloverSeedS5(rolloverCount, pidSeedS5);

        var compCrcInput = new byte[1 + data.Length + 2];
        compCrcInput[0] = mode.TimestampCrcMask; // mode & 0x1F for complement in EF
        compSlice.CopyTo(compCrcInput.AsSpan(1));
        BinaryPrimitives.WriteUInt16LittleEndian(compCrcInput.AsSpan(1 + data.Length), timestamp);
        uint s5 = SafetyCrc.ComputeS5Raw(compCrcInput, rcSeedS5);

        // Split 24-bit S5: S5_lo(2) before timestamp, S5_hi(1) after
        // Per CSS IXSFAext.c: [S5_lo(2)] [Timestamp(2)] [S5_hi(1)]
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), (ushort)(s5 & 0xFFFF)); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), timestamp); off += 2;
        output[off++] = (byte)((s5 >> 16) & 0xFF);

        return off;
    }

    private static SafetyDecodeResult DecodeExtendedLong(ReadOnlySpan<byte> input, int dataLen,
        ushort pidSeedS3, uint pidSeedS5, ushort rolloverCount)
    {
        int expectedSize = 2 * dataLen + 8;
        if (input.Length < expectedSize)
            return SafetyDecodeResult.Error("Input too short for extended long frame");

        int off = 0;
        var data = input.Slice(off, dataLen).ToArray(); off += dataLen;
        var mode = new ModeByte(input[off++]);
        ushort wireCrcA = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(off)); off += 2;
        var compData = input.Slice(off, dataLen).ToArray(); off += dataLen;
        // Extended Long: [S5_lo(2)] [Timestamp(2)] [S5_hi(1)]
        ushort s5Lo = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(off)); off += 2;
        ushort timestamp = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(off)); off += 2;
        byte s5Hi = input[off++];

        // Validate actual vs complement
        for (int i = 0; i < dataLen; i++)
        {
            if ((byte)(data[i] ^ 0xFF) != compData[i])
                return SafetyDecodeResult.Error("Actual vs complement data mismatch");
        }

        // Validate actual CRC-S3
        ushort rcSeedS3 = SafetyCrc.PidRolloverSeedS3(rolloverCount, pidSeedS3);
        ushort aCrc = SafetyCrc.ComputeS3(mode.DataCrcMask, rcSeedS3);
        aCrc = SafetyCrc.ComputeS3(data, aCrc);
        if (aCrc != wireCrcA)
            return SafetyDecodeResult.Error("Actual data CRC-S3 mismatch");

        // Validate complement CRC-S5
        uint rcSeedS5 = SafetyCrc.PidRolloverSeedS5(rolloverCount, pidSeedS5);
        var compCrcInput = new byte[1 + dataLen + 2];
        compCrcInput[0] = mode.TimestampCrcMask;
        compData.CopyTo(compCrcInput.AsSpan(1));
        BinaryPrimitives.WriteUInt16LittleEndian(compCrcInput.AsSpan(1 + dataLen), timestamp);
        uint expectedS5 = SafetyCrc.ComputeS5Raw(compCrcInput, rcSeedS5);

        uint wireS5 = (uint)(s5Lo | ((uint)s5Hi << 16));
        if (wireS5 != (expectedS5 & 0x00FFFFFF))
            return SafetyDecodeResult.Error("Complement CRC-S5 mismatch");

        return new SafetyDecodeResult(data, mode, timestamp, true, null);
    }

    // ==================== Time Coordination Messages ====================

    /// <summary>
    /// Encode a Base Format Time Coordination message (6 bytes).
    /// Sent by consumer to producer in response to Ping_Count change.
    /// Wire format: [AckByte(1)] [ConsumerTimeValue(2)] [AckByte2(1)] [CRC-S3(2)]
    /// </summary>
    public static int EncodeTimeCoordination(Span<byte> output,
        byte pingCountReply, ushort consumerTimeValue, ushort cidSeedS3)
    {
        int off = 0;

        // Build AckByte: Ping_Count_Reply in bits 1:0, Ping_Response=1 in bit 3, parity in bit 7
        byte ackByte = 0;
        ackByte |= (byte)(pingCountReply & 0x03);           // Ping_Count_Reply (bits 1:0)
        ackByte |= 0x08;                                     // Ping_Response = 1 (bit 3)
        // Reserved bits 2, 4, 5, 6 = 0
        // Parity (bit 7): even parity of bits 0-6
        int bitCount = 0;
        for (int i = 0; i < 7; i++)
            if ((ackByte & (1 << i)) != 0) bitCount++;
        if (bitCount % 2 != 0)
            ackByte |= 0x80; // set parity bit

        output[off++] = ackByte;

        // Consumer_Time_Value (UINT, little-endian)
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), consumerTimeValue); off += 2;

        // AckByte2: ((AckByte ^ 0xFF) & 0x55) | (AckByte & 0xAA)
        byte ackByte2 = (byte)(((ackByte ^ 0xFF) & 0x55) | (ackByte & 0xAA));
        output[off++] = ackByte2;

        // CRC-S3 over AckByte + ConsumerTimeValue, seeded by CID
        ushort crc = SafetyCrc.ComputeS3(ackByte, cidSeedS3);
        crc = SafetyCrc.ComputeS3(consumerTimeValue, crc);
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), crc); off += 2;

        return off; // always 6
    }

    /// <summary>
    /// Encode an Extended Format Time Coordination message (6 bytes).
    /// Same size as Base but uses CRC-S5 instead of CRC-S3 + duplicate ack byte.
    /// Wire format: [AckByte(1)] [ConsumerTimeValue(2)] [CRC_S5_0(1)] [CRC_S5_1(1)] [CRC_S5_2(1)]
    /// </summary>
    public static int EncodeTimeCoordinationExtended(Span<byte> output,
        byte pingCountReply, ushort consumerTimeValue, uint pidSeedS5)
    {
        int off = 0;

        // Build AckByte: same as Base format
        byte ackByte = 0;
        ackByte |= (byte)(pingCountReply & 0x03);
        ackByte |= 0x08; // Ping_Response = 1
        int bitCount = 0;
        for (int i = 0; i < 7; i++)
            if ((ackByte & (1 << i)) != 0) bitCount++;
        if (bitCount % 2 != 0)
            ackByte |= 0x80;

        output[off++] = ackByte;

        // Consumer_Time_Value (UINT, little-endian)
        BinaryPrimitives.WriteUInt16LittleEndian(output.Slice(off), consumerTimeValue); off += 2;

        // CRC-S5 chained: PID seed → ackByte → consumerTimeValue (no rollover)
        uint s5 = SafetyCrc.ComputeS5Raw(new[] { ackByte }, pidSeedS5);
        Span<byte> tsBuf = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(tsBuf, consumerTimeValue);
        s5 = SafetyCrc.ComputeS5Raw(tsBuf, s5);

        // Split 24-bit CRC into 3 bytes
        output[off++] = (byte)(s5 & 0xFF);
        output[off++] = (byte)((s5 >> 8) & 0xFF);
        output[off++] = (byte)((s5 >> 16) & 0xFF);

        return off; // always 6
    }
}

/// <summary>Result of decoding a safety frame.</summary>
public readonly struct SafetyDecodeResult
{
    public byte[] ActualData { get; }
    public ModeByte Mode { get; }
    public ushort Timestamp { get; }
    public bool CrcValid { get; }
    public string? ErrorMessage { get; }

    public SafetyDecodeResult(byte[] data, ModeByte mode, ushort timestamp, bool valid, string? error)
    {
        ActualData = data;
        Mode = mode;
        Timestamp = timestamp;
        CrcValid = valid;
        ErrorMessage = error;
    }

    public static SafetyDecodeResult Error(string message) =>
        new([], default, 0, false, message);
}
