using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// IMessageManager that parses EtherNet/IP encapsulation messages out of a
/// byte stream. Designed for use over TCP — the caller accumulates raw
/// bytes into a buffer and calls TryParse in a loop, advancing by
/// `consumed` after each successful parse.
///
/// Dispatches by EncapsulationHeader.Command to the appropriate typed
/// message class (NopMessage, RegisterSessionMessage, etc.). Unknown
/// commands fall back to the generic EncapsulationMessage with the raw
/// payload — caller can decide whether to drop or handle.
/// </summary>
public sealed class EncapsulationMessageManager : IMessageManager
{
    public IMessage? TryParse(ReadOnlySpan<byte> data, IPEndPoint remoteEndpoint, out int consumed)
    {
        consumed = 0;
        if (data.Length < EncapsulationHeader.Size) return null; // need at least the header

        var header = EncapsulationHeader.Parse(data);
        int totalSize = EncapsulationHeader.Size + header.Length;
        if (data.Length < totalSize) return null; // need more bytes for the full payload

        var payload = data.Slice(EncapsulationHeader.Size, header.Length);
        consumed = totalSize;

        return header.Command switch
        {
            EncapsulationCommand.Nop               => NopMessage.Parse(header, payload, remoteEndpoint),
            EncapsulationCommand.RegisterSession   => RegisterSessionMessage.Parse(header, payload, remoteEndpoint),
            EncapsulationCommand.UnregisterSession => UnregisterSessionMessage.Parse(header, payload, remoteEndpoint),
            EncapsulationCommand.ListIdentity      => ListIdentityMessage.Parse(header, payload, remoteEndpoint),
            EncapsulationCommand.ListServices      => ListServicesMessage.Parse(header, payload, remoteEndpoint),
            EncapsulationCommand.SendRRData        => SendRRDataMessage.Parse(header, payload, remoteEndpoint),
            EncapsulationCommand.SendUnitData      => SendUnitDataMessage.Parse(header, payload, remoteEndpoint),
            _ => new EncapsulationMessage
            {
                Header = header,
                Payload = payload.ToArray(),
                RemoteEndpoint = remoteEndpoint,
            },
        };
    }
}
