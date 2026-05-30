using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// Encapsulation ListIdentity (0x0063). Discovery query.
///
/// Request: header only. Response: header + CPF (one ItemIdentity item).
/// Both directions share this type — distinguish by whether ResponsePayload is set.
/// </summary>
public sealed class ListIdentityMessage : ISerializableMessage
{
    public uint SessionHandle { get; init; }
    public EncapsulationStatus Status { get; init; }
    public ulong SenderContext { get; init; }
    public IPEndPoint RemoteEndpoint { get; init; } = null!;

    /// <summary>If non-empty, this is a response carrying CPF identity data. Empty = request.</summary>
    public ReadOnlyMemory<byte> ResponsePayload { get; init; }

    public int WireSize => EncapsulationHeader.Size + ResponsePayload.Length;

    public void WriteTo(Span<byte> destination)
    {
        new EncapsulationHeader
        {
            Command = EncapsulationCommand.ListIdentity,
            Length = (ushort)ResponsePayload.Length,
            SessionHandle = SessionHandle,
            Status = Status,
            SenderContext = SenderContext,
        }.WriteTo(destination);
        ResponsePayload.Span.CopyTo(destination.Slice(EncapsulationHeader.Size));
    }

    public static ListIdentityMessage Parse(EncapsulationHeader header, ReadOnlySpan<byte> payload, IPEndPoint endpoint)
        => new()
        {
            SessionHandle = header.SessionHandle,
            Status = header.Status,
            SenderContext = header.SenderContext,
            ResponsePayload = payload.ToArray(),
            RemoteEndpoint = endpoint,
        };
}
