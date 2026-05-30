using System.Net;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// Parses raw network bytes into typed IMessage objects.
///
/// Works for both datagram (UDP) and stream (TCP) transports:
///   - UDP: TryParse called once per datagram. consumed is typically the
///     whole packet; a return of null means "I don't recognize this packet".
///   - TCP: TryParse called against accumulated buffered bytes. If a complete
///     message is present, returns it and sets consumed to that message's
///     length so the caller can advance its buffer. If not enough bytes for
///     a complete message, returns null with consumed=0 — the caller should
///     wait for more data.
///
/// Implementations decide what messages they understand.
/// </summary>
public interface IMessageManager
{
    /// <summary>
    /// Try to parse one message from the front of <paramref name="data"/>.
    /// </summary>
    /// <param name="data">Raw bytes (one datagram, or the unprocessed front of a TCP stream).</param>
    /// <param name="remoteEndpoint">Sender's endpoint.</param>
    /// <param name="consumed">Bytes consumed (set even on success only).</param>
    /// <returns>The parsed message, or null if not recognized / not enough bytes.</returns>
    IMessage? TryParse(ReadOnlySpan<byte> data, IPEndPoint remoteEndpoint, out int consumed);
}
