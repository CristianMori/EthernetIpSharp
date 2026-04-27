using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EipSim.Cip;
using EipSim.Device;
using EipSim.Protocol;

namespace EipSim.Protocol.Tests;

public class EncapsulationTests : IAsyncLifetime
{
    private VirtualDevice _device = null!;
    private CancellationTokenSource _cts = null!;
    private int _port;

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

        _device = new VirtualDevice(identity, IPAddress.Loopback, "TestDevice");
        _port = GetFreeTcpPort();
        await _device.StartAsync(_port, GetFreeTcpPort(), _cts.Token);
    }

    public async Task DisposeAsync()
    {
        _cts.Cancel();
        await _device.DisposeAsync();
        _cts.Dispose();
    }

    private async Task<TcpClient> ConnectAsync()
    {
        var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _port);
        return client;
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
    public async Task RegisterSession_ReturnsValidHandle()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();

        // Build RegisterSession request
        var request = new EncapsulationHeader
        {
            Command = EncapsulationCommand.RegisterSession,
            Length = 4,
            SessionHandle = 0,
            Status = 0,
            SenderContext = 0x1234567890ABCDEF,
            Options = 0,
        };

        var buf = new byte[EncapsulationHeader.Size + 4];
        request.WriteTo(buf);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(24), 1); // Protocol version
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(26), 0); // Options

        await stream.WriteAsync(buf);

        // Read response
        var responseBuf = new byte[EncapsulationHeader.Size + 4];
        await ReadExactAsync(stream, responseBuf);

        var response = EncapsulationHeader.Parse(responseBuf);
        Assert.Equal(EncapsulationCommand.RegisterSession, response.Command);
        Assert.Equal(EncapsulationStatus.Success, response.Status);
        Assert.NotEqual(0u, response.SessionHandle);
        Assert.Equal(request.SenderContext, response.SenderContext);
    }

    [Fact]
    public async Task ListIdentity_ReturnsDeviceInfo()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();

        // Send ListIdentity
        var request = new EncapsulationHeader
        {
            Command = EncapsulationCommand.ListIdentity,
            Length = 0,
        };
        var buf = new byte[EncapsulationHeader.Size];
        request.WriteTo(buf);
        await stream.WriteAsync(buf);

        // Read response header
        var headerBuf = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, headerBuf);
        var response = EncapsulationHeader.Parse(headerBuf);

        Assert.Equal(EncapsulationCommand.ListIdentity, response.Command);
        Assert.Equal(EncapsulationStatus.Success, response.Status);
        Assert.True(response.Length > 0);

        // Read payload
        var payload = new byte[response.Length];
        await ReadExactAsync(stream, payload);

        // Parse CPF
        var items = CpfParser.Parse(payload);
        Assert.Single(items);
        Assert.Equal(CpfItemType.CipIdentity, items[0].TypeId);

        // Parse identity payload: encap protocol version (2) + socket addr (16) + identity attrs
        var idBytes = items[0].Data.ToArray();
        Assert.True(idBytes.Length > 18 + 2, "Identity payload too short");

        ushort encapVersion = BinaryPrimitives.ReadUInt16LittleEndian(idBytes);
        Assert.Equal(1, encapVersion);

        // Skip socket address (16 bytes) — identity attributes start at offset 18
        int attrOffset = 18;
        ushort vendorId = BinaryPrimitives.ReadUInt16LittleEndian(idBytes.AsSpan(attrOffset));
        Assert.Equal(42, vendorId);

        ushort deviceType = BinaryPrimitives.ReadUInt16LittleEndian(idBytes.AsSpan(attrOffset + 2));
        Assert.Equal(0x0C, deviceType);

        ushort productCode = BinaryPrimitives.ReadUInt16LittleEndian(idBytes.AsSpan(attrOffset + 4));
        Assert.Equal(1, productCode);
    }

    [Fact]
    public async Task SendRRData_NoSession_ReturnsError()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();

        // Don't register — send SendRRData directly
        var mrRequest = new byte[] { 0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x01 };
        var cpfBuf = new byte[256];
        int cpfLen = CpfParser.Write(cpfBuf, [
            new() { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
            new() { TypeId = CpfItemType.UnconnectedData, Data = mrRequest },
        ]);
        var payload = new byte[6 + cpfLen];
        cpfBuf.AsSpan(0, cpfLen).CopyTo(payload.AsSpan(6));

        var header = new EncapsulationHeader
        {
            Command = EncapsulationCommand.SendRRData,
            Length = (ushort)payload.Length,
            SessionHandle = 0xDEADBEEF,
        };
        var buf = new byte[EncapsulationHeader.Size + payload.Length];
        header.WriteTo(buf);
        payload.CopyTo(buf.AsSpan(EncapsulationHeader.Size));
        await stream.WriteAsync(buf);

        var responseBuf = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, responseBuf);
        var response = EncapsulationHeader.Parse(responseBuf);

        Assert.Equal(EncapsulationStatus.InvalidSessionHandle, response.Status);
    }

    [Fact]
    public async Task SendRRData_WrongSessionHandle_ReturnsError()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();

        // Register a valid session
        uint validSession = await RegisterSessionAsync(stream);
        Assert.NotEqual(0u, validSession);

        // Send SendRRData with a DIFFERENT session handle
        uint wrongSession = validSession + 999;
        var mrRequest = new byte[] { 0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x01 };
        var cpfBuf = new byte[256];
        int cpfLen = CpfParser.Write(cpfBuf, [
            new() { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
            new() { TypeId = CpfItemType.UnconnectedData, Data = mrRequest },
        ]);
        var payload = new byte[6 + cpfLen];
        cpfBuf.AsSpan(0, cpfLen).CopyTo(payload.AsSpan(6));

        var header = new EncapsulationHeader
        {
            Command = EncapsulationCommand.SendRRData,
            Length = (ushort)payload.Length,
            SessionHandle = wrongSession, // Valid format but wrong handle
        };
        var buf = new byte[EncapsulationHeader.Size + payload.Length];
        header.WriteTo(buf);
        payload.CopyTo(buf.AsSpan(EncapsulationHeader.Size));
        await stream.WriteAsync(buf);

        var responseBuf = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, responseBuf);
        var response = EncapsulationHeader.Parse(responseBuf);

        Assert.Equal(EncapsulationStatus.InvalidSessionHandle, response.Status);
    }

    [Fact]
    public async Task SendRRData_GetIdentityAttribute_ReturnsVendorId()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();

        // First register a session
        uint sessionHandle = await RegisterSessionAsync(stream);

        // Build a GetAttributeSingle request for Identity.VendorId (Class 1, Instance 1, Attr 1)
        // MR Request: Service (0x0E) + Path Size (3 words) + Path + no data
        var mrRequest = new byte[]
        {
            0x0E,       // Get_Attribute_Single
            0x03,       // Path size: 3 words = 6 bytes
            0x20, 0x01, // Class 0x01 (Identity)
            0x24, 0x01, // Instance 1
            0x30, 0x01, // Attribute 1 (Vendor ID)
        };

        // Build SendRRData with UCMM format
        var cpfBuf = new byte[256];
        var cpfItems = new CpfItem[]
        {
            new() { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
            new() { TypeId = CpfItemType.UnconnectedData, Data = mrRequest },
        };
        int cpfLen = CpfParser.Write(cpfBuf, cpfItems);

        // SendRRData payload: Interface Handle (4) + Timeout (2) + CPF
        var sendRRPayload = new byte[6 + cpfLen];
        cpfBuf.AsSpan(0, cpfLen).CopyTo(sendRRPayload.AsSpan(6));

        var request = new EncapsulationHeader
        {
            Command = EncapsulationCommand.SendRRData,
            Length = (ushort)sendRRPayload.Length,
            SessionHandle = sessionHandle,
        };
        var requestBuf = new byte[EncapsulationHeader.Size + sendRRPayload.Length];
        request.WriteTo(requestBuf);
        sendRRPayload.CopyTo(requestBuf.AsSpan(EncapsulationHeader.Size));

        await stream.WriteAsync(requestBuf);

        // Read response
        var headerBuf = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, headerBuf);
        var responseHeader = EncapsulationHeader.Parse(headerBuf);

        Assert.Equal(EncapsulationCommand.SendRRData, responseHeader.Command);
        Assert.Equal(EncapsulationStatus.Success, responseHeader.Status);

        var responsePayload = new byte[responseHeader.Length];
        await ReadExactAsync(stream, responsePayload);

        // Parse response CPF: skip interface handle (4) + timeout (2)
        var responseCpf = CpfParser.Parse(responsePayload.AsSpan(6));
        Assert.Equal(2, responseCpf.Length);
        Assert.Equal(CpfItemType.UnconnectedData, responseCpf[1].TypeId);

        // Parse MR response: service|0x80 (1) + reserved (1) + general status (1) + additional status size (1) + data
        var mrResponseBytes = responseCpf[1].Data.ToArray();
        byte replyService = mrResponseBytes[0];
        Assert.Equal(0x0E | 0x80, replyService);
        byte generalStatus = mrResponseBytes[2];
        Assert.Equal(0, generalStatus); // Success

        byte addStatusSize = mrResponseBytes[3];
        int dataOffset = 4 + addStatusSize * 2;

        // Vendor ID should be 42
        ushort vendorId = BinaryPrimitives.ReadUInt16LittleEndian(mrResponseBytes.AsSpan(dataOffset));
        Assert.Equal(42, vendorId);
    }

    private async Task<uint> RegisterSessionAsync(NetworkStream stream)
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
        var response = EncapsulationHeader.Parse(responseBuf);
        return response.SessionHandle;
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
