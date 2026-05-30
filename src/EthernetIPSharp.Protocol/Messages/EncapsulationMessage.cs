using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol.Messages;

/// <summary>
/// EtherNet/IP encapsulation message — a 24-byte header followed by an
/// optional payload. The framing format used on TCP port 44818 (and the
/// connectionless variants on UDP port 44818).
///
/// One incoming TCP byte stream may contain many of these messages back-to-back;
/// the EncapsulationMessageManager handles framing.
/// </summary>
public sealed class EncapsulationMessage : ISerializableMessage
{
    /// <summary>Parsed header fields. (Length is auto-computed at serialization from Payload.Length.)</summary>
    public EncapsulationHeader Header { get; init; }

    /// <summary>Variable-size payload following the header. Empty for header-only commands (Nop, etc).</summary>
    public ReadOnlyMemory<byte> Payload { get; init; }

    public IPEndPoint RemoteEndpoint { get; init; } = null!;

    public int WireSize => EncapsulationHeader.Size + Payload.Length;

    public void WriteTo(Span<byte> destination)
    {
        // Header.Length must reflect the actual payload — overwrite whatever the caller put there.
        var hdr = Header;
        hdr.Length = (ushort)Payload.Length;
        hdr.WriteTo(destination);
        Payload.Span.CopyTo(destination.Slice(EncapsulationHeader.Size));
    }
}
