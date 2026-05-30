using System.Net;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// IMessageManager that parses CPF-format datagrams (UDP).
///
/// Currently knows about CpfConnectedDataMessage (SequencedAddress + ConnectedData).
/// New variants (Class 0 addresses, multicast, ListIdentity replies, etc.)
/// can be added here without changing the transport layer.
/// </summary>
public sealed class CpfMessageManager : IMessageManager
{
    public IMessage? TryParse(ReadOnlySpan<byte> data, IPEndPoint remoteEndpoint, out int consumed)
    {
        var msg = CpfConnectedDataMessage.TryParse(data, remoteEndpoint);
        // UDP datagrams are atomic — we always "consume" the whole packet,
        // even if we couldn't parse it (caller will drop it).
        consumed = data.Length;
        return msg;
    }
}
