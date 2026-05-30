using System.Buffers.Binary;
using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// Encapsulation SendRRData (0x006F). Unconnected explicit messaging (UCMM).
///
/// Wire layout (after the 24-byte encapsulation header):
///   InterfaceHandle(4) + Timeout(2) + CPF { NullAddress(0x0000) + UnconnectedData(0x00B2) }
///
/// The unconnected data carries a CIP MessageRouter request/reply.
/// </summary>
public sealed class SendRRDataMessage : ISerializableMessage
{
    public uint SessionHandle { get; init; }
    public EncapsulationStatus Status { get; init; }
    public ulong SenderContext { get; init; }
    public uint InterfaceHandle { get; init; }
    public ushort Timeout { get; init; }
    /// <summary>The CIP MessageRouter packet bytes (everything inside the CPF UnconnectedData item).</summary>
    public ReadOnlyMemory<byte> CipData { get; init; }
    public IPEndPoint RemoteEndpoint { get; init; } = null!;

    private const ushort NullAddressTypeId = 0x0000;
    private const ushort UnconnectedDataTypeId = 0x00B2;
    private const int CpfHeaderOverhead = 2 /*itemCount*/ + 4 /*nullAddr hdr*/ + 4 /*data hdr*/;
    private const int PreambleSize = 6; // InterfaceHandle + Timeout

    public int WireSize => EncapsulationHeader.Size + PreambleSize + CpfHeaderOverhead + CipData.Length;

    public void WriteTo(Span<byte> destination)
    {
        int payloadLen = PreambleSize + CpfHeaderOverhead + CipData.Length;
        new EncapsulationHeader
        {
            Command = EncapsulationCommand.SendRRData,
            Length = (ushort)payloadLen,
            SessionHandle = SessionHandle,
            Status = Status,
            SenderContext = SenderContext,
        }.WriteTo(destination);

        int o = EncapsulationHeader.Size;
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(o), InterfaceHandle); o += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), Timeout); o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), 2); o += 2; // item count

        // Null address item
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), NullAddressTypeId); o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), 0); o += 2;

        // Unconnected data item
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), UnconnectedDataTypeId); o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), (ushort)CipData.Length); o += 2;
        CipData.Span.CopyTo(destination.Slice(o));
    }

    public static SendRRDataMessage? Parse(EncapsulationHeader header, ReadOnlySpan<byte> payload, IPEndPoint endpoint)
    {
        if (payload.Length < PreambleSize + CpfHeaderOverhead) return null;

        int o = 0;
        uint interfaceHandle = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(o)); o += 4;
        ushort timeout = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        ushort itemCount = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        if (itemCount < 2) return null;

        // Null address item
        ushort addrType = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        ushort addrLen = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        if (addrType != NullAddressTypeId || addrLen != 0) return null;
        o += addrLen;

        // Unconnected data item
        if (o + 4 > payload.Length) return null;
        ushort dataType = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        ushort dataLen = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        if (dataType != UnconnectedDataTypeId) return null;
        if (o + dataLen > payload.Length) return null;

        return new SendRRDataMessage
        {
            SessionHandle = header.SessionHandle,
            Status = header.Status,
            SenderContext = header.SenderContext,
            InterfaceHandle = interfaceHandle,
            Timeout = timeout,
            CipData = payload.Slice(o, dataLen).ToArray(),
            RemoteEndpoint = endpoint,
        };
    }
}
