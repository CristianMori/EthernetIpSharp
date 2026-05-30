using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>Encapsulation Nop (0x0000). No payload, no reply.</summary>
public sealed class NopMessage : ISerializableMessage
{
    public ulong SenderContext { get; init; }
    public IPEndPoint RemoteEndpoint { get; init; } = null!;

    public int WireSize => EncapsulationHeader.Size;

    public void WriteTo(Span<byte> destination)
    {
        new EncapsulationHeader
        {
            Command = EncapsulationCommand.Nop,
            SenderContext = SenderContext,
        }.WriteTo(destination);
    }

    public static NopMessage Parse(EncapsulationHeader header, ReadOnlySpan<byte> payload, IPEndPoint endpoint)
        => new() { SenderContext = header.SenderContext, RemoteEndpoint = endpoint };
}
