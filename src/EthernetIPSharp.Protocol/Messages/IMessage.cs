using System.Net;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// Transport-agnostic marker for a network message. Concrete implementations
/// parse from / serialize to raw bytes and expose typed properties for the
/// rest of the stack to consume.
///
/// The same interface is used for UDP (datagram) and TCP (stream) messages
/// — the transport layer handles the framing differences.
///
/// RemoteEndpoint is captured at receive time and attached for diagnostic /
/// correlation purposes. For sends it tells the transport where to deliver.
/// </summary>
public interface IMessage
{
    /// <summary>Where the message came from (receive) or is going to (send).</summary>
    IPEndPoint RemoteEndpoint { get; }
}

/// <summary>Marker for messages that can be serialized to wire bytes.</summary>
public interface ISerializableMessage : IMessage
{
    /// <summary>Number of bytes required to serialize this message.</summary>
    int WireSize { get; }

    /// <summary>Serialize into the given span (must be at least WireSize bytes).</summary>
    void WriteTo(Span<byte> destination);
}
