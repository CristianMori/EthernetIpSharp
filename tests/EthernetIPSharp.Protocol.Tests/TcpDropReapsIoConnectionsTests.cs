using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;
using EthernetIPSharp.Device;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Protocol.Tests;

/// <summary>
/// Regression test: an originator that RegisterSessions and Forward_Opens a
/// valid assembly pair, then drops the TCP socket without sending Forward_Close
/// (and without ever producing any O→T UDP), must not leave its IoConnection
/// alive on the device. The CIP watchdog is held off until the first inbound
/// frame (CIP Vol 1 §3-4.5.2), so without the TCP-close reap the connection
/// would pin a producer Thread + WatchdogTimer indefinitely — repeating the
/// pattern exhausts resources and locks out legitimate scanners.
/// </summary>
public class TcpDropReapsIoConnectionsTests : IAsyncLifetime
{
    private VirtualDevice _device = null!;
    private CancellationTokenSource _cts = null!;
    private int _tcpPort;

    public async Task InitializeAsync()
    {
        _cts = new CancellationTokenSource();
        var identity = new IdentityInfo
        {
            VendorId = 42,
            DeviceType = 0x0C,
            ProductCode = 1,
            MajorRevision = 1,
            MinorRevision = 0,
            SerialNumber = 0x12345678,
            ProductName = "TestDevice",
        };

        _device = new StandardDevice(identity, IPAddress.Loopback, "TestDevice");
        _device.AddAssembly(100, 16, "Produced");
        _device.AddAssembly(101, 16, "Consumed");
        _device.AddAssembly(150, 0, "Config");

        _tcpPort = GetFreeTcpPort();
        int udpPort = GetFreeTcpPort();
        await _device.StartAsync(_tcpPort, udpPort, _cts.Token);
    }

    public async Task DisposeAsync()
    {
        _cts.Cancel();
        await _device.DisposeAsync();
        _cts.Dispose();
    }

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    [Fact]
    public async Task TcpDropWithoutForwardClose_ReapsIoConnection()
    {
        // Open a TCP connection, RegisterSession, Forward_Open — the normal
        // path up to the moment production would start.
        var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();

        uint sessionHandle = await RegisterSessionAsync(stream);
        var (status, _) = await SendForwardOpenAsync(stream, sessionHandle,
            connSerial: 1,
            otRpi: 20000,
            toRpi: 20000,
            otSize: 16,
            toSize: 16,
            consumedInstance: 101,
            producedInstance: 100,
            configInstance: 150);

        Assert.Equal(0, status);
        Assert.Single(_device.ConnectionManager.ActiveConnections);

        // Drop the socket hard — LingerOption 0 forces RST, mirroring an
        // attacker that walks away mid-connection.
        client.Client.LingerState = new LingerOption(enable: true, seconds: 0);
        client.Close();

        // The socket-closed handler runs on the TcpSocket read thread after
        // the stream drains; give it a bounded window to reap.
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline && _device.ConnectionManager.ActiveConnections.Count > 0)
            await Task.Delay(25);

        Assert.Empty(_device.ConnectionManager.ActiveConnections);
    }

    [Fact]
    public async Task MultipleHitAndRunPeers_LeaveNoConnectionsBehind()
    {
        // Replay the attack a few times to prove the reap is not a one-shot
        // — the Python port fix was motivated by the slot cap exhausting
        // after max_connections hit-and-run peers.
        for (int i = 0; i < 8; i++)
        {
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
            var stream = client.GetStream();

            uint sessionHandle = await RegisterSessionAsync(stream);
            var (status, _) = await SendForwardOpenAsync(stream, sessionHandle,
                connSerial: (ushort)(100 + i),
                otRpi: 20000,
                toRpi: 20000,
                otSize: 16,
                toSize: 16,
                consumedInstance: 101,
                producedInstance: 100,
                configInstance: 150);

            Assert.Equal(0, status);

            client.Client.LingerState = new LingerOption(enable: true, seconds: 0);
            client.Close();
        }

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline && _device.ConnectionManager.ActiveConnections.Count > 0)
            await Task.Delay(25);

        Assert.Empty(_device.ConnectionManager.ActiveConnections);
    }

    // ---- Wire helpers (same shape as ForwardOpenTests, kept local to this
    //      file so the regression stands on its own and doesn't share fixture
    //      state with other tests). ----

    private async Task<(byte generalStatus, byte[] data)> SendForwardOpenAsync(
        NetworkStream stream, uint sessionHandle,
        ushort connSerial, uint otRpi, uint toRpi, ushort otSize, ushort toSize,
        uint consumedInstance, uint producedInstance, uint configInstance)
    {
        var connPath = new byte[]
        {
            0x20, 0x04,
            0x24, (byte)configInstance,
            0x2C, (byte)consumedInstance,
            0x2C, (byte)producedInstance,
        };

        ushort otParams = (ushort)(0x4000 | (otSize & 0x01FF));
        ushort toParams = (ushort)(0x4000 | (toSize & 0x01FF));

        var fwdOpenData = new byte[36 + connPath.Length];
        int off = 0;
        fwdOpenData[off++] = 0x0A;
        fwdOpenData[off++] = 0xFA;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), 0x11111111u | connSerial); off += 4; // OT (originator picks for us if P2P OT target; harmless here)
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), 0x00ABCD00u | connSerial); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), connSerial); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), 99); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), 0xABCDu); off += 4;
        fwdOpenData[off++] = 0;
        off += 3;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), otRpi); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), otParams); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), toRpi); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), toParams); off += 2;
        fwdOpenData[off++] = 0x01;
        fwdOpenData[off++] = (byte)(connPath.Length / 2);
        connPath.CopyTo(fwdOpenData.AsSpan(off));

        var mrRequest = new byte[6 + fwdOpenData.Length];
        mrRequest[0] = 0x54;
        mrRequest[1] = 0x02;
        mrRequest[2] = 0x20; mrRequest[3] = 0x06;
        mrRequest[4] = 0x24; mrRequest[5] = 0x01;
        fwdOpenData.CopyTo(mrRequest.AsSpan(6));

        return await SendUcmmRequestAsync(stream, sessionHandle, mrRequest);
    }

    private async Task<(byte generalStatus, byte[] data)> SendUcmmRequestAsync(
        NetworkStream stream, uint sessionHandle, byte[] mrRequest)
    {
        var cpfBuf = new byte[1024];
        var cpfItems = new CpfItem[]
        {
            new() { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
            new() { TypeId = CpfItemType.UnconnectedData, Data = mrRequest },
        };
        int cpfLen = CpfParser.Write(cpfBuf, cpfItems);

        var payload = new byte[6 + cpfLen];
        cpfBuf.AsSpan(0, cpfLen).CopyTo(payload.AsSpan(6));

        var header = new EncapsulationHeader
        {
            Command = EncapsulationCommand.SendRRData,
            Length = (ushort)payload.Length,
            SessionHandle = sessionHandle,
        };

        var requestBuf = new byte[EncapsulationHeader.Size + payload.Length];
        header.WriteTo(requestBuf);
        payload.CopyTo(requestBuf.AsSpan(EncapsulationHeader.Size));
        await stream.WriteAsync(requestBuf);

        var headerBuf = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, headerBuf);
        var responseHeader = EncapsulationHeader.Parse(headerBuf);

        var responsePayload = new byte[responseHeader.Length];
        await ReadExactAsync(stream, responsePayload);

        var responseCpf = CpfParser.Parse(responsePayload.AsSpan(6));
        var mrResponseBytes = responseCpf[1].Data.ToArray();

        byte generalStatus = mrResponseBytes[2];
        byte addStatusSize = mrResponseBytes[3];
        int dataOffset = 4 + addStatusSize * 2;
        var data = mrResponseBytes.AsSpan(dataOffset).ToArray();

        return (generalStatus, data);
    }

    private static async Task<uint> RegisterSessionAsync(NetworkStream stream)
    {
        var request = new EncapsulationHeader
        {
            Command = EncapsulationCommand.RegisterSession,
            Length = 4,
        };
        var buf = new byte[EncapsulationHeader.Size + 4];
        request.WriteTo(buf);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(24), 1);
        await stream.WriteAsync(buf);

        var responseBuf = new byte[EncapsulationHeader.Size + 4];
        await ReadExactAsync(stream, responseBuf);
        return EncapsulationHeader.Parse(responseBuf).SessionHandle;
    }

    private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(totalRead));
            if (n == 0) throw new Exception("Connection closed");
            totalRead += n;
        }
    }
}
