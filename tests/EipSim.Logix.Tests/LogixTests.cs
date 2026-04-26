using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EipSim.Cip;
using EipSim.Logix;
using EipSim.Protocol;

namespace EipSim.Logix.Tests;

public class LogixTests : IAsyncLifetime
{
    private LogixDispatcher _logix = null!;
    private EipAdapter _adapter = null!;
    private CancellationTokenSource _cts = null!;
    private int _tcpPort;

    public async Task InitializeAsync()
    {
        _cts = new CancellationTokenSource();
        _logix = new LogixDispatcher();

        // Add test tags
        var rate = _logix.Tags.AddTag("rate", LogixDataTypes.DINT);
        rate.Write(0, 534);

        var temp = _logix.Tags.AddTag("temperature", LogixDataTypes.REAL);
        temp.Write(0, 72.5f);

        _logix.Tags.AddTag("counts", LogixDataTypes.INT, elementCount: 10);

        var identity = new IdentityInfo
        {
            VendorId = 1,
            DeviceType = 0x0E, // Programmable Logic Controller
            ProductCode = 55,
            MajorRevision = 32,
            MinorRevision = 11,
            SerialNumber = 0xDEAD,
            ProductName = "EipSim Logix Emulator",
        };

        _adapter = new EipAdapter(_logix, identity);
        _tcpPort = GetFreePort();
        await _adapter.ListenAsync(IPAddress.Loopback, _tcpPort, _cts.Token);
    }

    public async Task DisposeAsync()
    {
        _cts.Cancel();
        await _adapter.DisposeAsync();
        _cts.Dispose();
    }

    [Fact]
    public async Task ReadTag_BySymbolicName_ReturnsDintValue()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Read Tag "rate" — symbolic segment: 91 04 72 61 74 65
        var path = new byte[] { 0x91, 0x04, 0x72, 0x61, 0x74, 0x65 }; // "rate"
        var requestData = new byte[] { 0x01, 0x00 }; // element count = 1

        var (status, data) = await SendCipServiceAsync(stream, session, 0x4C, path, requestData);

        Assert.Equal(0, status); // Success
        Assert.True(data.Length >= 6); // tag_type (2) + DINT (4)

        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(data);
        Assert.Equal(LogixDataTypes.DINT, tagType);

        int value = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(2));
        Assert.Equal(534, value);
    }

    [Fact]
    public async Task ReadTag_BySymbolicName_ReturnsRealValue()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // "temperature" = 91 0B 74 65 6D 70 65 72 61 74 75 72 65 00 (11 chars + pad)
        var path = BuildSymbolicPath("temperature");
        var requestData = new byte[] { 0x01, 0x00 };

        var (status, data) = await SendCipServiceAsync(stream, session, 0x4C, path, requestData);

        Assert.Equal(0, status);
        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(data);
        Assert.Equal(LogixDataTypes.REAL, tagType);

        float value = BinaryPrimitives.ReadSingleLittleEndian(data.AsSpan(2));
        Assert.Equal(72.5f, value);
    }

    [Fact]
    public async Task WriteTag_BySymbolicName_UpdatesValueAndFiresEvent()
    {
        Tag? changedTag = null;
        TagChangeInfo changeInfo = default;
        var tag = _logix.Tags.FindByName("rate")!;
        tag.ValueChanged += (t, info) => { changedTag = t; changeInfo = info; };

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Write Tag "rate" = 999
        var path = BuildSymbolicPath("rate");
        var writeData = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(writeData, LogixDataTypes.DINT); // tag type
        BinaryPrimitives.WriteUInt16LittleEndian(writeData.AsSpan(2), 1); // element count
        BinaryPrimitives.WriteInt32LittleEndian(writeData.AsSpan(4), 999); // value

        var (status, _) = await SendCipServiceAsync(stream, session, 0x4D, path, writeData);

        Assert.Equal(0, status);

        // Verify the value changed
        Assert.Equal(999, tag.Read<int>());

        // Verify the event fired
        Assert.NotNull(changedTag);
        Assert.Equal("rate", changedTag!.Name);
        Assert.Equal(0, changeInfo.ByteOffset);
        Assert.Equal(4, changeInfo.ByteLength);
    }

    [Fact]
    public async Task WriteTag_TypeMismatch_ReturnsError_ValueUnchanged()
    {
        var tag = _logix.Tags.FindByName("rate")!;
        int originalValue = tag.Read<int>();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Try to write REAL type to a DINT tag
        var path = BuildSymbolicPath("rate");
        var writeData = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(writeData, LogixDataTypes.REAL); // wrong type!
        BinaryPrimitives.WriteUInt16LittleEndian(writeData.AsSpan(2), 1);
        BinaryPrimitives.WriteInt32LittleEndian(writeData.AsSpan(4), 42);

        var (status, _) = await SendCipServiceAsync(stream, session, 0x4D, path, writeData);

        Assert.Equal(0xFF, status); // General error (type mismatch)
        Assert.Equal(originalValue, tag.Read<int>()); // Value must not have changed
    }

    [Fact]
    public async Task ReadTag_NonexistentTag_ReturnsError()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var path = BuildSymbolicPath("nonexistent");
        var requestData = new byte[] { 0x01, 0x00 };

        var (status, _) = await SendCipServiceAsync(stream, session, 0x4C, path, requestData);

        Assert.Equal(0x05, status); // Path destination unknown
    }

    [Fact]
    public async Task AnyTagChanged_FiresOnWrite()
    {
        Tag? globalChanged = null;
        _logix.Tags.AnyTagChanged += (t, _) => globalChanged = t;

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var path = BuildSymbolicPath("temperature");
        var writeData = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(writeData, LogixDataTypes.REAL);
        BinaryPrimitives.WriteUInt16LittleEndian(writeData.AsSpan(2), 1);
        BinaryPrimitives.WriteSingleLittleEndian(writeData.AsSpan(4), 100.0f);

        await SendCipServiceAsync(stream, session, 0x4D, path, writeData);

        Assert.NotNull(globalChanged);
        Assert.Equal("temperature", globalChanged!.Name);
    }

    // --- Helpers ---

    private static byte[] BuildSymbolicPath(string name)
    {
        int padded = name.Length % 2 != 0 ? name.Length + 1 : name.Length;
        var path = new byte[2 + padded];
        path[0] = 0x91; // ANSI Extended Symbolic Segment
        path[1] = (byte)name.Length;
        System.Text.Encoding.ASCII.GetBytes(name, path.AsSpan(2));
        return path;
    }

    private async Task<(byte generalStatus, byte[] data)> SendCipServiceAsync(
        NetworkStream stream, uint session, byte serviceCode, byte[] pathBytes, byte[] serviceData)
    {
        // Build MR request: service + path_size_words + path + data
        int pathSizeWords = pathBytes.Length / 2;
        var mrRequest = new byte[2 + pathBytes.Length + serviceData.Length];
        mrRequest[0] = serviceCode;
        mrRequest[1] = (byte)pathSizeWords;
        pathBytes.CopyTo(mrRequest.AsSpan(2));
        serviceData.CopyTo(mrRequest.AsSpan(2 + pathBytes.Length));

        // Wrap in CPF
        var cpfBuf = new byte[1024];
        var cpfItems = new CpfItem[]
        {
            new() { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
            new() { TypeId = CpfItemType.UnconnectedData, Data = mrRequest },
        };
        int cpfLen = CpfParser.Write(cpfBuf, cpfItems);

        // SendRRData payload
        var payload = new byte[6 + cpfLen];
        cpfBuf.AsSpan(0, cpfLen).CopyTo(payload.AsSpan(6));

        var header = new EncapsulationHeader
        {
            Command = EncapsulationCommand.SendRRData,
            Length = (ushort)payload.Length,
            SessionHandle = session,
        };

        var requestBuf = new byte[EncapsulationHeader.Size + payload.Length];
        header.WriteTo(requestBuf);
        payload.CopyTo(requestBuf.AsSpan(EncapsulationHeader.Size));
        await stream.WriteAsync(requestBuf);

        // Read response
        var headerBuf = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, headerBuf);
        var respHeader = EncapsulationHeader.Parse(headerBuf);

        var respPayload = new byte[respHeader.Length];
        await ReadExactAsync(stream, respPayload);

        var respCpf = CpfParser.Parse(respPayload.AsSpan(6));
        var mrResp = respCpf[1].Data.ToArray();

        byte generalStatus = mrResp[2];
        byte addStatusSize = mrResp[3];
        int dataOffset = 4 + addStatusSize * 2;
        var data = mrResp.AsSpan(dataOffset).ToArray();

        return (generalStatus, data);
    }

    private async Task<uint> RegisterSessionAsync(NetworkStream stream)
    {
        var req = new EncapsulationHeader { Command = EncapsulationCommand.RegisterSession, Length = 4 };
        var buf = new byte[EncapsulationHeader.Size + 4];
        req.WriteTo(buf);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(24), 1);
        await stream.WriteAsync(buf);

        var resp = new byte[EncapsulationHeader.Size + 4];
        await ReadExactAsync(stream, resp);
        return EncapsulationHeader.Parse(resp).SessionHandle;
    }

    private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read));
            if (n == 0) throw new Exception("Connection closed");
            read += n;
        }
    }

    private static int GetFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
