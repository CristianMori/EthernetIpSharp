using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace EipSim.Protocol;

/// <summary>
/// EtherNet/IP UDP transport on port 2222 (0x08AE).
/// Handles Class 0/1 I/O data in CPF format without encapsulation header.
/// Format: ItemCount(2) + SequencedAddress(0x8002, connId, encapSeqNum) + ConnectedData(0x00B1, data)
/// </summary>
public sealed class EipUdpTransport : IEipUdpTransport
{
    public const int IoPort = 0x08AE; // 2222

    private readonly IPEndPoint _bindEndpoint;
    private UdpClient? _client;
    private CancellationTokenSource? _cts;

    /// <summary>Called when I/O data arrives. Parameters: connectionId, data (class 1 has seq count stripped).</summary>
    public event Action<uint, ReadOnlyMemory<byte>>? DataReceived;

    public EipUdpTransport(IPEndPoint bindEndpoint)
    {
        _bindEndpoint = bindEndpoint;
    }

    public Task StartAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _client = new UdpClient();
        _client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _client.Client.Bind(_bindEndpoint);

        _ = ReceiveLoopAsync(_cts.Token);
        return Task.CompletedTask;
    }

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

    private void ProcessIncomingPacket(byte[] data, IPEndPoint remoteEndpoint)
    {
        if (data.Length < 18) return; // Minimum: 2 (count) + 4+8 (seq addr) + 4 (conn data header)

        // Parse CPF items (no encapsulation header)
        ushort itemCount = BinaryPrimitives.ReadUInt16LittleEndian(data);
        if (itemCount < 2) return;

        int offset = 2;

        // Item 1: Sequenced Address (0x8002)
        ushort addrTypeId = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset)); offset += 2;
        ushort addrLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset)); offset += 2;

        if (addrTypeId != 0x8002 || addrLength != 8) return;

        uint connectionId = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset)); offset += 4;
        uint encapSeqNum = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset)); offset += 4;

        // Item 2: Connected Data (0x00B1)
        ushort dataTypeId = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset)); offset += 2;
        ushort dataLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset)); offset += 2;

        if (dataTypeId != 0x00B1) return;

        var ioData = data.AsMemory(offset, dataLength);

        DataReceived?.Invoke(connectionId, ioData);
    }

    /// <summary>
    /// Send I/O data to the scanner (T→O production).
    /// Builds the CPF packet with Sequenced Address + Connected Data.
    /// </summary>
    public void SendIoData(IPEndPoint destination, uint connectionId, uint encapSeqNum, ReadOnlySpan<byte> data)
    {
        // Build packet: ItemCount(2) + SequencedAddress + ConnectedData
        int packetSize = 2 + (4 + 8) + (4 + data.Length);
        var packet = new byte[packetSize];
        int offset = 0;

        // Item count = 2
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), 2); offset += 2;

        // Sequenced Address item
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), 0x8002); offset += 2; // Type
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), 8); offset += 2;       // Length
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(offset), connectionId); offset += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(offset), encapSeqNum); offset += 4;

        // Connected Data item
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), 0x00B1); offset += 2; // Type
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(offset), (ushort)data.Length); offset += 2;
        data.CopyTo(packet.AsSpan(offset));

        _client?.Send(packet, packet.Length, destination);
    }

    public ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _client?.Dispose();
        _cts?.Dispose();
        return ValueTask.CompletedTask;
    }
}
