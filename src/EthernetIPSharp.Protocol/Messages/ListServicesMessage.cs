using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// Encapsulation ListServices (0x0004).
///
/// Request: header only. Response: header + CPF (one CommServices item, 0x0100).
/// </summary>
public sealed class ListServicesMessage : ISerializableMessage
{
    public uint SessionHandle { get; init; }
    public EncapsulationStatus Status { get; init; }
    public ulong SenderContext { get; init; }
    public IPEndPoint RemoteEndpoint { get; init; } = null!;

    /// <summary>If non-empty, this is a response. Empty = request.</summary>
    public ReadOnlyMemory<byte> ResponsePayload { get; init; }

    public int WireSize => EncapsulationHeader.Size + ResponsePayload.Length;

    public void WriteTo(Span<byte> destination)
    {
        new EncapsulationHeader
        {
            Command = EncapsulationCommand.ListServices,
            Length = (ushort)ResponsePayload.Length,
            SessionHandle = SessionHandle,
            Status = Status,
            SenderContext = SenderContext,
        }.WriteTo(destination);
        ResponsePayload.Span.CopyTo(destination.Slice(EncapsulationHeader.Size));
    }

    public static ListServicesMessage Parse(EncapsulationHeader header, ReadOnlySpan<byte> payload, IPEndPoint endpoint)
        => new()
        {
            SessionHandle = header.SessionHandle,
            Status = header.Status,
            SenderContext = header.SenderContext,
            ResponsePayload = payload.ToArray(),
            RemoteEndpoint = endpoint,
        };
}
