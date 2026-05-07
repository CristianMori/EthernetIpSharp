using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// EtherNet/IP UDP transport on port 2222 (0x08AE).
/// Handles Class 0/1 I/O data in CPF format without encapsulation header.
///
/// Wire format:
///   ItemCount(2) + SequencedAddress(0x8002: connId(4) + encapSeqNum(4))
///                + ConnectedData(0x00B1: data(N))
/// </summary>
public sealed class EipUdpTransport : IEipUdpTransport
{
    /// <summary>Standard EtherNet/IP UDP I/O port (0x08AE = 2222).</summary>
    public const int IoPort = 0x08AE;

    /// <summary>CPF header overhead: ItemCount(2) + SeqAddr header(4) + SeqAddr data(8) + ConnData header(4) = 18.</summary>
    private const int CpfOverhead = 18;

    private readonly IPEndPoint _bindEndpoint;
    private UdpClient? _client;
    private CancellationTokenSource? _cts;

    /// <summary>Fired when I/O data arrives. Parameters: connectionId, I/O data (includes CIP seq count for Class 1).</summary>
    public event Action<uint, ReadOnlyMemory<byte>>? DataReceived;

    /// <summary>Fired with sender endpoint when I/O data arrives. Used to learn the scanner's actual UDP port.</summary>
    public event Action<uint, IPEndPoint>? DataReceivedWithSender;

    /// <summary>Create a UDP transport bound to the given endpoint.</summary>
    public EipUdpTransport(IPEndPoint bindEndpoint)
    {
        _bindEndpoint = bindEndpoint;
    }

    /// <summary>Bind the UDP socket and start the receive loop.</summary>
    public Task StartAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _client = new UdpClient();
        _client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _client.Client.Bind(_bindEndpoint);

        _ = ReceiveLoopAsync(_cts.Token);
        return Task.CompletedTask;
    }

    /// <summary>Receive loop — runs until cancelled. Processes each incoming UDP packet.</summary>
    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _client!.ReceiveAsync(ct);
                ProcessIncomingPacket(result.Buffer, result.RemoteEndPoint);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { } // Transient errors, continue
        }
    }

    /// <summary>
    /// Parse a received UDP packet as CPF I/O data.
    /// Validates item types and lengths before firing events.
    /// </summary>
    private void ProcessIncomingPacket(byte[] data, IPEndPoint remoteEndpoint)
    {
        if (data.Length < CpfOverhead) return;

        ushort itemCount = BinaryPrimitives.ReadUInt16LittleEndian(data);
        if (itemCount < 2) return;

        int offset = 2;

        // Item 1: Sequenced Address (0x8002) — 8 bytes: connId(4) + encapSeqNum(4)
        ushort addrTypeId = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset)); offset += 2;
        ushort addrLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset)); offset += 2;

        if (addrTypeId != 0x8002 || addrLength != 8) return;

        uint connectionId = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset)); offset += 4;
        // encapSeqNum — skip (used by the transport layer for packet ordering, not needed by application)
        offset += 4;

        // Item 2: Connected Data (0x00B1)
        if (offset + 4 > data.Length) return;
        ushort dataTypeId = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset)); offset += 2;
        ushort dataLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset)); offset += 2;

        if (dataTypeId != 0x00B1) return;
        if (offset + dataLength > data.Length) return; // Truncated packet

        var ioData = data.AsMemory(offset, dataLength);

        DataReceived?.Invoke(connectionId, ioData);
        DataReceivedWithSender?.Invoke(connectionId, remoteEndpoint);
    }

    /// <summary>
    /// Send I/O data to a remote endpoint.
    /// Builds the CPF packet: Sequenced Address (0x8002) + Connected Data (0x00B1).
    /// Uses ArrayPool to avoid per-send heap allocation.
    /// </summary>
    public void SendIoData(IPEndPoint destination, uint connectionId, uint encapSeqNum, ReadOnlySpan<byte> data)
    {
        int packetSize = CpfOverhead + data.Length;
        var packet = ArrayPool<byte>.Shared.Rent(packetSize);
        try
        {
            int offset = 0;

            // Item count = 2
            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), 2); offset += 2;

            // Sequenced Address item
            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), 0x8002); offset += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), 8); offset += 2;
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(offset), connectionId); offset += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(offset), encapSeqNum); offset += 4;

            // Connected Data item
            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), 0x00B1); offset += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), (ushort)data.Length); offset += 2;
            data.CopyTo(packet.AsSpan(offset));

            _client?.Send(packet, packetSize, destination);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(packet);
        }
    }

    /// <summary>Stop the receive loop and release the UDP socket.</summary>
    public ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _client?.Dispose();
        _cts?.Dispose();
        return ValueTask.CompletedTask;
    }
}
