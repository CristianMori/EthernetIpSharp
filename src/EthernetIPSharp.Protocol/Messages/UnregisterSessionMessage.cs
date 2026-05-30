using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>Encapsulation UnregisterSession (0x0066). Header-only. No reply.</summary>
public sealed class UnregisterSessionMessage : ISerializableMessage
{
    public uint SessionHandle { get; init; }
    public ulong SenderContext { get; init; }
    public IPEndPoint RemoteEndpoint { get; init; } = null!;

    public int WireSize => EncapsulationHeader.Size;

    public void WriteTo(Span<byte> destination)
    {
        new EncapsulationHeader
        {
            Command = EncapsulationCommand.UnregisterSession,
            SessionHandle = SessionHandle,
            SenderContext = SenderContext,
        }.WriteTo(destination);
    }

    public static UnregisterSessionMessage Parse(EncapsulationHeader header, ReadOnlySpan<byte> payload, IPEndPoint endpoint)
        => new()
        {
            SessionHandle = header.SessionHandle,
            SenderContext = header.SenderContext,
            RemoteEndpoint = endpoint,
        };
}
