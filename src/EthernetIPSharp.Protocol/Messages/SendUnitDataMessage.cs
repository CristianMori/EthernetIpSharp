using System.Buffers.Binary;
using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// Encapsulation SendUnitData (0x0070). Connected explicit messaging.
///
/// Wire layout (after the 24-byte encapsulation header):
///   InterfaceHandle(4) + Timeout(2) + CPF { ConnectedAddress(0x00A1) + ConnectedData(0x00B1) }
///
/// ConnectedAddress carries a 4-byte connection ID; ConnectedData carries
/// the CIP service request/reply.
/// </summary>
public sealed class SendUnitDataMessage : ISerializableMessage
{
    public uint SessionHandle { get; init; }
    public EncapsulationStatus Status { get; init; }
    public ulong SenderContext { get; init; }
    public uint InterfaceHandle { get; init; }
    public ushort Timeout { get; init; }
    public uint ConnectionId { get; init; }
    /// <summary>CIP MessageRouter bytes (everything inside the CPF ConnectedData item).</summary>
    public ReadOnlyMemory<byte> CipData { get; init; }
    public IPEndPoint RemoteEndpoint { get; init; } = null!;

    private const ushort ConnectedAddressTypeId = 0x00A1;
    private const ushort ConnectedDataTypeId = 0x00B1;
    private const int CpfHeaderOverhead = 2 /*itemCount*/ + 4 /*addr hdr*/ + 4 /*addr connId*/ + 4 /*data hdr*/;
    private const int PreambleSize = 6;

    public int WireSize => EncapsulationHeader.Size + PreambleSize + CpfHeaderOverhead + CipData.Length;

    public void WriteTo(Span<byte> destination)
    {
        int payloadLen = PreambleSize + CpfHeaderOverhead + CipData.Length;
        new EncapsulationHeader
        {
            Command = EncapsulationCommand.SendUnitData,
            Length = (ushort)payloadLen,
            SessionHandle = SessionHandle,
            Status = Status,
            SenderContext = SenderContext,
        }.WriteTo(destination);

        int o = EncapsulationHeader.Size;
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(o), InterfaceHandle); o += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), Timeout); o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), 2); o += 2; // item count

        // Connected address item: type + length + connectionId
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), ConnectedAddressTypeId); o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), 4); o += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(o), ConnectionId); o += 4;

        // Connected data item
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), ConnectedDataTypeId); o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(o), (ushort)CipData.Length); o += 2;
        CipData.Span.CopyTo(destination.Slice(o));
    }

    public static SendUnitDataMessage? Parse(EncapsulationHeader header, ReadOnlySpan<byte> payload, IPEndPoint endpoint)
    {
        if (payload.Length < PreambleSize + CpfHeaderOverhead) return null;

        int o = 0;
        uint interfaceHandle = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(o)); o += 4;
        ushort timeout = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        ushort itemCount = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        if (itemCount < 2) return null;

        ushort addrType = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        ushort addrLen = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        if (addrType != ConnectedAddressTypeId || addrLen != 4) return null;
        uint connectionId = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(o)); o += 4;

        if (o + 4 > payload.Length) return null;
        ushort dataType = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        ushort dataLen = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(o)); o += 2;
        if (dataType != ConnectedDataTypeId) return null;
        if (o + dataLen > payload.Length) return null;

        return new SendUnitDataMessage
        {
            SessionHandle = header.SessionHandle,
            Status = header.Status,
            SenderContext = header.SenderContext,
            InterfaceHandle = interfaceHandle,
            Timeout = timeout,
            ConnectionId = connectionId,
            CipData = payload.Slice(o, dataLen).ToArray(),
            RemoteEndpoint = endpoint,
        };
    }
}
