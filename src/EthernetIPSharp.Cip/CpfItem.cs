using System.Buffers.Binary;

namespace EthernetIPSharp.Cip;

/// <summary>
/// Common Packet Format item type IDs.
/// </summary>
public enum CpfItemType : ushort
{
    /// <summary>Null address — no routing info. Used for UCMM messages.</summary>
    NullAddress = 0x0000,
    /// <summary>CIP Identity item returned in ListIdentity replies.</summary>
    CipIdentity = 0x000C,
    /// <summary>Connected address — contains a 4-byte connection ID.</summary>
    ConnectedAddress = 0x00A1,
    /// <summary>Connected transport data (Class 2/3 over TCP).</summary>
    ConnectedData = 0x00B1,
    /// <summary>Unconnected message data (UCMM — MR request/response).</summary>
    UnconnectedData = 0x00B2,
    /// <summary>ListServices response item.</summary>
    ListServicesResponse = 0x0100,
    /// <summary>Socket address info for originator-to-target direction.</summary>
    SockaddrInfoOtoT = 0x8000,
    /// <summary>Socket address info for target-to-originator direction.</summary>
    SockaddrInfoTtoO = 0x8001,
    /// <summary>Sequenced address — connection ID + encapsulation sequence number. Used for Class 0/1 UDP.</summary>
    SequencedAddress = 0x8002,
}

/// <summary>
/// A single item in the Common Packet Format.
/// Contains a type ID and variable-length data.
/// </summary>
public readonly struct CpfItem
{
    /// <summary>The type of this CPF item.</summary>
    public CpfItemType TypeId { get; init; }

    /// <summary>The item data. Length may be zero (e.g. NullAddress).</summary>
    public ReadOnlyMemory<byte> Data { get; init; }
}

/// <summary>
/// Common Packet Format parser/writer.
/// Wire format: item_count (UINT) + array of { type_id (UINT), length (UINT), data (byte[length]) }.
/// Used inside SendRRData, SendUnitData, and Class 0/1 UDP packets.
/// </summary>
public static class CpfParser
{
    /// <summary>
    /// Parse CPF items from a byte span.
    /// Returns an empty array if the data is too short.
    /// Stops parsing if the data is truncated mid-item.
    /// </summary>
    public static CpfItem[] Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
            return [];

        ushort itemCount = BinaryPrimitives.ReadUInt16LittleEndian(data);
        var items = new CpfItem[itemCount];
        int offset = 2;
        int parsed = 0;

        for (int i = 0; i < itemCount; i++)
        {
            // Need at least 4 bytes for type + length header
            if (offset + 4 > data.Length)
                break;

            var typeId = (CpfItemType)BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset));
            ushort length = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset + 2));
            offset += 4;

            // Check that the item data fits in the remaining buffer
            if (offset + length > data.Length)
                break;

            items[i] = new CpfItem
            {
                TypeId = typeId,
                Data = data.Slice(offset, length).ToArray(),
            };
            offset += length;
            parsed++;
        }

        // If we parsed fewer items than declared, trim the array
        if (parsed < itemCount)
            Array.Resize(ref items, parsed);

        return items;
    }

    /// <summary>
    /// Write CPF items to a byte buffer.
    /// Returns the total number of bytes written.
    /// Throws ArgumentException if the buffer is too small.
    /// </summary>
    public static int Write(Span<byte> buffer, ReadOnlySpan<CpfItem> items)
    {
        // Calculate required size: 2 (count) + sum of (4 + data.Length) per item
        int required = 2;
        foreach (var item in items)
            required += 4 + item.Data.Length;

        if (buffer.Length < required)
            throw new ArgumentException(
                $"CPF write requires {required} bytes, buffer has {buffer.Length}");

        int offset = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer, (ushort)items.Length);
        offset += 2;

        foreach (var item in items)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(buffer.Slice(offset), (ushort)item.TypeId);
            BinaryPrimitives.WriteUInt16LittleEndian(buffer.Slice(offset + 2), (ushort)item.Data.Length);
            offset += 4;
            item.Data.Span.CopyTo(buffer.Slice(offset));
            offset += item.Data.Length;
        }

        return offset;
    }
}
