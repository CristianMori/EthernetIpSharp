using System.Buffers.Binary;
using System.Net;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// CPF (Common Packet Format) packet carrying connected I/O data over UDP:
/// item count = 2, SequencedAddress (0x8002) + ConnectedData (0x00B1).
///
/// This is the standard form for Class 0/1 cyclic I/O on port 2222.
/// </summary>
public sealed class CpfConnectedDataMessage : ISerializableMessage
{
    /// <summary>CPF header overhead: ItemCount(2) + SeqAddr header(4) + SeqAddr data(8) + ConnData header(4) = 18.</summary>
    public const int CpfOverhead = 18;

    private const ushort SequencedAddressTypeId = 0x8002;
    private const ushort ConnectedDataTypeId = 0x00B1;

    /// <summary>O→T (consumer side) or T→O (producer side) connection ID — identifies which connection the data belongs to.</summary>
    public uint ConnectionId { get; init; }

    /// <summary>Encapsulation sequence number (CPF-level, separate from CIP Class 1 sequence).</summary>
    public uint EncapSequenceNumber { get; init; }

    /// <summary>Connected data payload (CIP I/O bytes; for Class 1 this still includes the 2-byte CIP sequence count).</summary>
    public ReadOnlyMemory<byte> Payload { get; init; }

    public IPEndPoint RemoteEndpoint { get; init; } = null!;

    public int WireSize => CpfOverhead + Payload.Length;

    public void WriteTo(Span<byte> dst) => WriteWire(dst, ConnectionId, EncapSequenceNumber, Payload.Span);

    /// <summary>Hot-path span-based writer. Use directly when sending I/O data to
    /// avoid allocating a CpfConnectedDataMessage object per produced frame.</summary>
    public static void WriteWire(Span<byte> dst, uint connectionId, uint encapSequenceNumber, ReadOnlySpan<byte> payload)
    {
        int o = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(dst.Slice(o), 2); o += 2; // item count
        BinaryPrimitives.WriteUInt16LittleEndian(dst.Slice(o), SequencedAddressTypeId); o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(dst.Slice(o), 8); o += 2; // address length
        BinaryPrimitives.WriteUInt32LittleEndian(dst.Slice(o), connectionId); o += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(dst.Slice(o), encapSequenceNumber); o += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(dst.Slice(o), ConnectedDataTypeId); o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(dst.Slice(o), (ushort)payload.Length); o += 2;
        payload.CopyTo(dst.Slice(o));
    }

    /// <summary>Try to parse a CPF SequencedAddress + ConnectedData packet. Returns null if the layout doesn't match.</summary>
    public static CpfConnectedDataMessage? TryParse(ReadOnlySpan<byte> data, IPEndPoint remoteEndpoint)
    {
        if (data.Length < CpfOverhead) return null;

        ushort itemCount = BinaryPrimitives.ReadUInt16LittleEndian(data);
        if (itemCount < 2) return null;

        int o = 2;
        ushort addrTypeId = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(o)); o += 2;
        ushort addrLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(o)); o += 2;
        if (addrTypeId != SequencedAddressTypeId || addrLength != 8) return null;

        uint connectionId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o)); o += 4;
        uint encapSeq = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o)); o += 4;

        if (o + 4 > data.Length) return null;
        ushort dataTypeId = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(o)); o += 2;
        ushort dataLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(o)); o += 2;
        if (dataTypeId != ConnectedDataTypeId) return null;
        if (o + dataLength > data.Length) return null;

        // Copy payload so the caller can retain it past the receive buffer's lifetime.
        var payload = data.Slice(o, dataLength).ToArray();

        return new CpfConnectedDataMessage
        {
            ConnectionId = connectionId,
            EncapSequenceNumber = encapSeq,
            Payload = payload,
            RemoteEndpoint = remoteEndpoint,
        };
    }
}
