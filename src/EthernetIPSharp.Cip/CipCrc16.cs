namespace EthernetIPSharp.Cip;

/// <summary>
/// 16-bit CRC used across the CIP wire spec (polynomial 0xA001, initial value 0,
/// byte-at-a-time little-endian, right-shift with XOR-back).  Same math as the
/// classic CRC-16/ARC family; the polynomial 0xA001 is the reversed form of
/// 0x8005.
///
/// The algorithm below matches the reference C implementation shipped with the
/// spec, and passes the two test vectors the spec quotes:
///   Calc([A2 03 C7 C2 C3])                 → 0x5159
///   Calc([A2 07 C7 A2 03 C7 C2 C3 C3])     → 0x26C7
/// </summary>
public static class CipCrc16
{
    /// <summary>Compute the CIP 16-bit CRC over <paramref name="bytes"/>.</summary>
    public static ushort Calc(ReadOnlySpan<byte> bytes)
    {
        ushort crc = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            crc ^= bytes[i];
            for (int j = 0; j < 8; j++)
            {
                bool carry = (crc & 1) != 0;
                crc = (ushort)(crc >> 1);
                if (carry) crc ^= 0xA001;
            }
        }
        return crc;
    }
}
