using System.Net;
using EthernetIPSharp.Protocol.Messages;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// UDP I/O transport abstraction for EtherNet/IP Class 0/1 data.
/// Implement to provide custom transport or mock for testing.
/// </summary>
public interface IEipUdpTransport : IAsyncDisposable
{
    /// <summary>
    /// Fired for every successfully parsed UDP message. Use pattern matching
    /// to dispatch on concrete type (CpfConnectedDataMessage, etc).
    /// </summary>
    event Action<IMessage>? MessageReceived;

    /// <summary>Start listening for UDP packets.</summary>
    Task StartAsync(CancellationToken ct);

    /// <summary>Send a typed message (uses the message's own serializer).</summary>
    void Send(ISerializableMessage message);

    /// <summary>
    /// Send I/O data to a remote endpoint. Kept as a span-based fast path —
    /// avoids the allocation of a CpfConnectedDataMessage on the hot send path.
    /// </summary>
    void SendIoData(IPEndPoint destination, uint connectionId, uint encapSeqNum, ReadOnlySpan<byte> data);
}
