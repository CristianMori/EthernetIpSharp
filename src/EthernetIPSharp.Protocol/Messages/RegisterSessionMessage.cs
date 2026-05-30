using System.Buffers.Binary;
using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// Encapsulation RegisterSession (0x0065). 4-byte payload: protocol version + options flags.
/// Used for both request and response — Status discriminates.
/// </summary>
public sealed class RegisterSessionMessage : ISerializableMessage
{
    public uint SessionHandle { get; init; }
    public EncapsulationStatus Status { get; init; }
    public ulong SenderContext { get; init; }
    public ushort ProtocolVersion { get; init; } = 1;
    public ushort OptionsFlags { get; init; }
    public IPEndPoint RemoteEndpoint { get; init; } = null!;

    public int WireSize => EncapsulationHeader.Size + 4;

    public void WriteTo(Span<byte> destination)
    {
        new EncapsulationHeader
        {
            Command = EncapsulationCommand.RegisterSession,
            Length = 4,
            SessionHandle = SessionHandle,
            Status = Status,
            SenderContext = SenderContext,
        }.WriteTo(destination);
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(EncapsulationHeader.Size), ProtocolVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(EncapsulationHeader.Size + 2), OptionsFlags);
    }

    public static RegisterSessionMessage? Parse(EncapsulationHeader header, ReadOnlySpan<byte> payload, IPEndPoint endpoint)
    {
        if (payload.Length < 4) return null;
        return new RegisterSessionMessage
        {
            SessionHandle = header.SessionHandle,
            Status = header.Status,
            SenderContext = header.SenderContext,
            ProtocolVersion = BinaryPrimitives.ReadUInt16LittleEndian(payload),
            OptionsFlags = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(2)),
            RemoteEndpoint = endpoint,
        };
    }
}
