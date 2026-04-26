using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace EipSim.Cip;

/// <summary>
/// Zero-allocation CIP data type serialization to/from little-endian byte spans.
/// </summary>
public static class CipDataSerializer
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ReadBool(ReadOnlySpan<byte> src) => src[0] != 0;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static sbyte ReadSint(ReadOnlySpan<byte> src) => (sbyte)src[0];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static short ReadInt(ReadOnlySpan<byte> src) => BinaryPrimitives.ReadInt16LittleEndian(src);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int ReadDint(ReadOnlySpan<byte> src) => BinaryPrimitives.ReadInt32LittleEndian(src);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static long ReadLint(ReadOnlySpan<byte> src) => BinaryPrimitives.ReadInt64LittleEndian(src);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte ReadUsint(ReadOnlySpan<byte> src) => src[0];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ushort ReadUint(ReadOnlySpan<byte> src) => BinaryPrimitives.ReadUInt16LittleEndian(src);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint ReadUdint(ReadOnlySpan<byte> src) => BinaryPrimitives.ReadUInt32LittleEndian(src);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong ReadUlint(ReadOnlySpan<byte> src) => BinaryPrimitives.ReadUInt64LittleEndian(src);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float ReadReal(ReadOnlySpan<byte> src) => BinaryPrimitives.ReadSingleLittleEndian(src);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static double ReadLreal(ReadOnlySpan<byte> src) => BinaryPrimitives.ReadDoubleLittleEndian(src);

    /// <summary>CIP SHORT_STRING: 1 byte length + ASCII chars.</summary>
    public static string ReadShortString(ReadOnlySpan<byte> src)
    {
        byte len = src[0];
        return Encoding.ASCII.GetString(src.Slice(1, len));
    }

    /// <summary>CIP STRING: 2 byte length (UINT) + ASCII chars.</summary>
    public static string ReadString(ReadOnlySpan<byte> src)
    {
        ushort len = BinaryPrimitives.ReadUInt16LittleEndian(src);
        return Encoding.ASCII.GetString(src.Slice(2, len));
    }

    // --- Writers ---

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteBool(Span<byte> dst, bool value) { dst[0] = value ? (byte)1 : (byte)0; return 1; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteSint(Span<byte> dst, sbyte value) { dst[0] = (byte)value; return 1; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteInt(Span<byte> dst, short value) { BinaryPrimitives.WriteInt16LittleEndian(dst, value); return 2; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteDint(Span<byte> dst, int value) { BinaryPrimitives.WriteInt32LittleEndian(dst, value); return 4; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteLint(Span<byte> dst, long value) { BinaryPrimitives.WriteInt64LittleEndian(dst, value); return 8; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteUsint(Span<byte> dst, byte value) { dst[0] = value; return 1; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteUint(Span<byte> dst, ushort value) { BinaryPrimitives.WriteUInt16LittleEndian(dst, value); return 2; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteUdint(Span<byte> dst, uint value) { BinaryPrimitives.WriteUInt32LittleEndian(dst, value); return 4; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteUlint(Span<byte> dst, ulong value) { BinaryPrimitives.WriteUInt64LittleEndian(dst, value); return 8; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteReal(Span<byte> dst, float value) { BinaryPrimitives.WriteSingleLittleEndian(dst, value); return 4; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int WriteLreal(Span<byte> dst, double value) { BinaryPrimitives.WriteDoubleLittleEndian(dst, value); return 8; }

    public static int WriteShortString(Span<byte> dst, string value)
    {
        byte len = (byte)Math.Min(value.Length, 255);
        dst[0] = len;
        Encoding.ASCII.GetBytes(value.AsSpan(0, len), dst.Slice(1));
        return 1 + len;
    }

    public static int WriteString(Span<byte> dst, string value)
    {
        ushort len = (ushort)Math.Min(value.Length, ushort.MaxValue);
        BinaryPrimitives.WriteUInt16LittleEndian(dst, len);
        Encoding.ASCII.GetBytes(value.AsSpan(0, len), dst.Slice(2));
        return 2 + len;
    }

    /// <summary>Returns the fixed size in bytes for a CIP data type, or -1 for variable-length types.</summary>
    public static int GetFixedSize(CipDataType type) => type switch
    {
        CipDataType.Bool => 1,
        CipDataType.Sint => 1,
        CipDataType.Int => 2,
        CipDataType.Dint => 4,
        CipDataType.Lint => 8,
        CipDataType.Usint => 1,
        CipDataType.Uint => 2,
        CipDataType.Udint => 4,
        CipDataType.Ulint => 8,
        CipDataType.Real => 4,
        CipDataType.Lreal => 8,
        CipDataType.Byte => 1,
        CipDataType.Word => 2,
        CipDataType.Dword => 4,
        CipDataType.Lword => 8,
        _ => -1, // variable length (strings)
    };
}
