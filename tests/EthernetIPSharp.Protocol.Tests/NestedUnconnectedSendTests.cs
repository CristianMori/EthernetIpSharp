using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;
using EthernetIPSharp.Device;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Protocol.Tests;

/// <summary>
/// Regression test for the Unconnected_Send recursion bomb.
/// A crafted SendRRData whose Unconnected_Send (0x52) wraps another
/// Unconnected_Send (0x52) targeting Class 0x06 Instance 1, repeated deeply,
/// used to recurse into HandleUnconnectedSend with no counter and crash the
/// process with StackOverflowException. The dispatch-depth cap must turn
/// this into a plain CIP error reply instead.
/// </summary>
public class NestedUnconnectedSendTests : IAsyncLifetime
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
    public async Task DeeplyNestedUnconnectedSend_ReturnsErrorWithoutStackOverflow()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();

        uint sessionHandle = await RegisterSessionAsync(stream);

        // Build the innermost MR: Get_Attributes_All on Identity (Class 0x01 Instance 1).
        // Any routable service is fine — the test is about surviving the wrapping, not the leaf.
        byte[] innermost = BuildMrRequest(serviceCode: 0x01,
            path: new byte[] { 0x20, 0x01, 0x24, 0x01 },
            data: ReadOnlyMemory<byte>.Empty);

        // Wrap it 10 times in Unconnected_Send → Class 0x06 Instance 1.
        // Three levels are allowed through, the fourth and beyond must be rejected
        // with a CIP error, never a crash.
        byte[] mr = innermost;
        for (int i = 0; i < 10; i++)
            mr = WrapInUnconnectedSend(mr);

        var (generalStatus, _) = await SendUcmmRequestAsync(stream, sessionHandle, mr);

        // The outer reply must be a CIP error, not a connection drop and not success.
        // 0x08 (Service not supported) is what the depth cap returns; the frame
        // round-trips cleanly if the server did not fall over.
        Assert.NotEqual(0x00, generalStatus);
    }

    private static byte[] WrapInUnconnectedSend(byte[] innerMr)
    {
        // Unconnected_Send data: priority(1) + timeout(1) + msg_length(UINT) + embedded_MR + [pad]
        //                       + route_path_size(1) + reserved(1) + route_path(2)
        bool pad = (innerMr.Length & 1) == 1;
        int routePathBytes = 2; // 1-port, no port details — minimal valid route
        int dataLen = 2 + 2 + innerMr.Length + (pad ? 1 : 0) + 2 + routePathBytes;

        var data = new byte[dataLen];
        int off = 0;
        data[off++] = 0x0A; // priority/time_tick
        data[off++] = 0xFA; // timeout_ticks
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(off), (ushort)innerMr.Length); off += 2;
        innerMr.CopyTo(data.AsSpan(off)); off += innerMr.Length;
        if (pad) data[off++] = 0;
        data[off++] = 1;    // route path size in words
        data[off++] = 0;    // reserved
        data[off++] = 0x01; // 1-port segment: port 1
        data[off++] = 0x00; // link address 0

        // Wrap in MR header: service 0x52 + path to Class 0x06 Instance 1
        return BuildMrRequest(0x52, new byte[] { 0x20, 0x06, 0x24, 0x01 }, data);
    }

    private static byte[] BuildMrRequest(byte serviceCode, byte[] path, ReadOnlyMemory<byte> data)
    {
        if ((path.Length & 1) != 0)
            throw new ArgumentException("Path must be a whole number of words.", nameof(path));

        var mr = new byte[2 + path.Length + data.Length];
        mr[0] = serviceCode;
        mr[1] = (byte)(path.Length / 2);
        path.CopyTo(mr.AsSpan(2));
        data.Span.CopyTo(mr.AsSpan(2 + path.Length));
        return mr;
    }

    private async Task<(byte generalStatus, byte[] data)> SendUcmmRequestAsync(
        NetworkStream stream, uint sessionHandle, byte[] mrRequest)
    {
        var cpfBuf = new byte[4096];
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
            if (n == 0) throw new IOException("Connection closed prematurely");
            totalRead += n;
        }
    }
}
