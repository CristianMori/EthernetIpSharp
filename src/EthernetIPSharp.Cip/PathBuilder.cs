using System.Buffers.Binary;

namespace EthernetIPSharp.Cip;

/// <summary>
/// Logical EPATH builder. Each field picks the smallest logical-segment
/// format that fits (8/16/32 bit) and emits the right pad byte for 16/32-bit
/// values. Null fields are skipped, so this also covers class-only and
/// class+instance paths.
/// </summary>
public static class PathBuilder
{
    // Logical segment format byte = 001 LLL FF (LLL = type, FF = format).
    private static readonly byte[] Class    = { 0x20, 0x21, 0x22 };
    private static readonly byte[] Instance = { 0x24, 0x25, 0x26 };
    private static readonly byte[] Attribute = { 0x30, 0x31, 0x32 };
    private static readonly byte[] Element  = { 0x28, 0x29, 0x2A };

    /// <summary>Build a logical EPATH from optional class/instance/attribute/element fields.</summary>
    public static byte[] BuildPath(uint? classId = null,
                                     uint? instanceId = null,
                                     ushort? attributeId = null,
                                     uint? elementId = null)
    {
        // Worst case = 4 fields × 6 bytes = 24, plenty of headroom.
        var buf = new byte[24];
        int offset = 0;
        if (classId.HasValue)     Emit(buf, ref offset, classId.Value,     Class);
        if (instanceId.HasValue)  Emit(buf, ref offset, instanceId.Value,  Instance);
        if (attributeId.HasValue) Emit(buf, ref offset, attributeId.Value, Attribute);
        if (elementId.HasValue)   Emit(buf, ref offset, elementId.Value,   Element);
        var result = new byte[offset];
        Array.Copy(buf, result, offset);
        return result;
    }

    private static void Emit(byte[] buf, ref int offset, uint value, byte[] segs)
    {
        if (value <= 0xFF)
        {
            buf[offset++] = segs[0];
            buf[offset++] = (byte)value;
        }
        else if (value <= 0xFFFF)
        {
            buf[offset++] = segs[1];
            buf[offset++] = 0;   // pad
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(offset), (ushort)value);
            offset += 2;
        }
        else
        {
            buf[offset++] = segs[2];
            buf[offset++] = 0;   // pad
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(offset), value);
            offset += 4;
        }
    }
}
