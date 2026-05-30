using System.Buffers;
using System.Net;
using EthernetIPSharp.Protocol.Messages;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// EtherNet/IP UDP I/O transport (port 2222 / 0x08AE).
///
/// Owns a UdpSocket for raw transport and a CpfMessageManager for
/// protocol parsing. Fires typed messages via MessageReceived.
/// </summary>
public sealed class EipUdpTransport : IEipUdpTransport
{
    /// <summary>Standard EtherNet/IP UDP I/O port (0x08AE = 2222).</summary>
    public const int IoPort = 0x08AE;

    private readonly IPEndPoint _bindEndpoint;
    private readonly UdpSocket _socket = new();
    private readonly IMessageManager _manager = new CpfMessageManager();

    /// <summary>Fired (on UdpSocket dispatch thread) for every parsed UDP message.</summary>
    public event Action<IMessage>? MessageReceived;

    /// <summary>Create a UDP transport bound to the given endpoint.</summary>
    public EipUdpTransport(IPEndPoint bindEndpoint)
    {
        _bindEndpoint = bindEndpoint;
        _socket.PacketReceived += OnRawPacketReceived;
    }

    /// <summary>Bind the UDP socket and start the receive + dispatch threads.</summary>
    public Task StartAsync(CancellationToken ct) => _socket.StartAsync(_bindEndpoint, ct);

    /// <summary>Parse the raw packet via the manager and fire MessageReceived.</summary>
    private void OnRawPacketReceived(ReadOnlyMemory<byte> data, IPEndPoint remoteEndpoint)
    {
        var msg = _manager.TryParse(data.Span, remoteEndpoint, out _);
        if (msg == null) return; // unknown / malformed — drop silently
        MessageReceived?.Invoke(msg);
    }

    /// <summary>Send a typed message. Serializes via WriteTo and pushes to the socket.</summary>
    public void Send(ISerializableMessage message)
    {
        var buf = ArrayPool<byte>.Shared.Rent(message.WireSize);
        try
        {
            message.WriteTo(buf);
            _socket.Send(message.RemoteEndpoint, buf.AsSpan(0, message.WireSize));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    /// <summary>Hot-path span-based send. Writes the CPF wire format directly
    /// into a pooled buffer — no per-frame heap allocations.</summary>
    public void SendIoData(IPEndPoint destination, uint connectionId, uint encapSeqNum, ReadOnlySpan<byte> data)
    {
        int wireSize = CpfConnectedDataMessage.CpfOverhead + data.Length;
        var buf = ArrayPool<byte>.Shared.Rent(wireSize);
        try
        {
            CpfConnectedDataMessage.WriteWire(buf, connectionId, encapSeqNum, data);
            _socket.Send(destination, buf.AsSpan(0, wireSize));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    /// <summary>Stop the receive loop and release the UDP socket.</summary>
    public ValueTask DisposeAsync() => _socket.DisposeAsync();
}
