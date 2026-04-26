using System.Buffers.Binary;

namespace EipSim.Cip;

public enum CpfItemType : ushort
{
    NullAddress = 0x0000,
    CipIdentity = 0x000C,
    ConnectedAddress = 0x00A1,
    ConnectedData = 0x00B1,
    UnconnectedData = 0x00B2,
    ListServicesResponse = 0x0100,
    SockaddrInfoOtoT = 0x8000,
    SockaddrInfoTtoO = 0x8001,
    SequencedAddress = 0x8002,
}

public readonly struct CpfItem
{
    public CpfItemType TypeId { get; init; }
    public ReadOnlyMemory<byte> Data { get; init; }
}

/// <summary>
/// Common Packet Format parser/writer (Vol2 §2-6).
/// Format: UINT item_count + array of { UINT type_id, UINT length, byte[length] data }
/// </summary>
public static class CpfParser
{
    public static CpfItem[] Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
            return [];

        ushort itemCount = BinaryPrimitives.ReadUInt16LittleEndian(data);
        var items = new CpfItem[itemCount];
        int offset = 2;

        for (int i = 0; i < itemCount; i++)
        {
            var typeId = (CpfItemType)BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset));
            ushort length = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset + 2));
            offset += 4;

            items[i] = new CpfItem
            {
                TypeId = typeId,
                Data = data.Slice(offset, length).ToArray(),
            };
            offset += length;
        }

        return items;
    }

    public static int Write(Span<byte> buffer, ReadOnlySpan<CpfItem> items)
    {
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
