using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EipSim.Cip;
using EipSim.Logix;
using EipSim.Protocol;

namespace EipSim.Logix.Tests;

/// <summary>
/// Tests that both addressing methods work for Read/Write Tag:
/// 1. Symbolic Segment Addressing (tag name in EPATH)
/// 2. Symbol Instance Addressing (Class 0x6B, Instance ID)
/// </summary>
public class AddressingTests : IAsyncLifetime
{
    private LogixDispatcher _logix = null!;
    private EipAdapter _adapter = null!;
    private CancellationTokenSource _cts = null!;
    private int _tcpPort;
    private Tag _rateTag = null!;
    private Tag _tempTag = null!;

    public async Task InitializeAsync()
    {
        _cts = new CancellationTokenSource();
        _logix = new LogixDispatcher();

        _rateTag = _logix.Tags.AddTag("rate", LogixDataTypes.DINT);
        _rateTag.Write(0, 534);

        _tempTag = _logix.Tags.AddTag("temperature", LogixDataTypes.REAL);
        _tempTag.Write(0, 72.5f);

        // No manual SyncCipInstances() — auto-sync should handle it

        var identity = new IdentityInfo
        {
            VendorId = 1, DeviceType = 0x0E, ProductCode = 55,
            MajorRevision = 32, MinorRevision = 11,
            SerialNumber = 0xBEEF, ProductName = "TestLogix",
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

    // ========== Symbolic Segment Addressing ==========

    [Fact]
    public async Task Symbolic_ReadTag_ReturnsDint()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Path: 91 04 72 61 74 65 = symbolic "rate"
        var path = BuildSymbolicPath("rate");
        var (status, data) = await SendCipServiceAsync(stream, session, 0x4C, path, ElementCount(1));

        Assert.Equal(0, status);
        Assert.Equal(LogixDataTypes.DINT, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(534, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(2)));
    }

    [Fact]
    public async Task Symbolic_WriteTag_UpdatesValue()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var path = BuildSymbolicPath("rate");
        var writeData = BuildWriteData(LogixDataTypes.DINT, 1, BitConverter.GetBytes(999));

        var (status, _) = await SendCipServiceAsync(stream, session, 0x4D, path, writeData);
        Assert.Equal(0, status);
        Assert.Equal(999, _rateTag.Read<int>());
    }

    // ========== Symbol Instance Addressing ==========

    [Fact]
    public async Task Instance_ReadTag_ReturnsDint()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Path: Class 0x6B, Instance = _rateTag.InstanceId
        var path = BuildInstancePath(_rateTag.InstanceId);
        var (status, data) = await SendCipServiceAsync(stream, session, 0x4C, path, ElementCount(1));

        Assert.Equal(0, status);
        Assert.Equal(LogixDataTypes.DINT, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(534, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(2)));
    }

    [Fact]
    public async Task Instance_ReadTag_ReturnsReal()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var path = BuildInstancePath(_tempTag.InstanceId);
        var (status, data) = await SendCipServiceAsync(stream, session, 0x4C, path, ElementCount(1));

        Assert.Equal(0, status);
        Assert.Equal(LogixDataTypes.REAL, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(72.5f, BinaryPrimitives.ReadSingleLittleEndian(data.AsSpan(2)));
    }

    [Fact]
    public async Task Instance_WriteTag_UpdatesValueAndFiresEvent()
    {
        Tag? changed = null;
        _rateTag.ValueChanged += (t, _) => changed = t;

        using var client = await ConnectAsync();
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var path = BuildInstancePath(_rateTag.InstanceId);
        var writeData = BuildWriteData(LogixDataTypes.DINT, 1, BitConverter.GetBytes(777));

        var (status, _) = await SendCipServiceAsync(stream, session, 0x4D, path, writeData);

        Assert.Equal(0, status);
        Assert.Equal(777, _rateTag.Read<int>());
        Assert.NotNull(changed);
    }

    [Fact]
    public async Task Instance_WriteTag_TypeMismatch_ReturnsError_ValueUnchanged()
    {
        int originalValue = _rateTag.Read<int>();

        using var client = await ConnectAsync();
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var path = BuildInstancePath(_rateTag.InstanceId);
        var writeData = BuildWriteData(LogixDataTypes.REAL, 1, BitConverter.GetBytes(1.0f));

        var (status, _) = await SendCipServiceAsync(stream, session, 0x4D, path, writeData);

        Assert.Equal(0xFF, status); // General error
        Assert.Equal(originalValue, _rateTag.Read<int>()); // Value must not change
    }

    [Fact]
    public async Task Instance_InvalidInstanceId_ReturnsPathDestinationUnknown()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var path = BuildInstancePath(99999);
        var (status, _) = await SendCipServiceAsync(stream, session, 0x4C, path, ElementCount(1));

        Assert.Equal(0x05, status); // PathDestinationUnknown — instance doesn't exist in Symbol class
    }

    // ========== Both methods return same data ==========

    [Fact]
    public async Task BothMethods_ReturnIdenticalData()
    {
        using var client = await ConnectAsync();
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Read via symbolic
        var symPath = BuildSymbolicPath("temperature");
        var (symStatus, symData) = await SendCipServiceAsync(stream, session, 0x4C, symPath, ElementCount(1));

        // Read via instance
        var instPath = BuildInstancePath(_tempTag.InstanceId);
        var (instStatus, instData) = await SendCipServiceAsync(stream, session, 0x4C, instPath, ElementCount(1));

        Assert.Equal(0, symStatus);
        Assert.Equal(0, instStatus);
        Assert.Equal(symData, instData);
    }

    // ========== Auto-sync: tags added after construction ==========

    [Fact]
    public async Task TagAddedAfterConstruction_AccessibleByInstance()
    {
        // Add a new tag AFTER the dispatcher was constructed
        var newTag = _logix.Tags.AddTag("lateTag", LogixDataTypes.INT);
        newTag.Write(0, (short)42);

        using var client = await ConnectAsync();
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Should be accessible by instance (auto-synced via TagAdded event)
        var path = BuildInstancePath(newTag.InstanceId);
        var (status, data) = await SendCipServiceAsync(stream, session, 0x4C, path, ElementCount(1));

        Assert.Equal(0, status);
        Assert.Equal(LogixDataTypes.INT, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(42, BinaryPrimitives.ReadInt16LittleEndian(data.AsSpan(2)));
    }

    // ========== Helpers ==========

    private static byte[] BuildSymbolicPath(string name)
    {
        int padded = name.Length % 2 != 0 ? name.Length + 1 : name.Length;
        var path = new byte[2 + padded];
        path[0] = 0x91;
        path[1] = (byte)name.Length;
        System.Text.Encoding.ASCII.GetBytes(name, path.AsSpan(2));
        return path;
    }

    /// <summary>Build Symbol Instance path: Class 0x6B + 16-bit Instance ID.</summary>
    private static byte[] BuildInstancePath(uint instanceId)
    {
        // 20 6B = Class 0x6B (8-bit), 25 00 xx xx = Instance (16-bit)
        var path = new byte[6];
        path[0] = 0x20; path[1] = 0x6B; // Class 0x6B
        path[2] = 0x25; path[3] = 0x00; // 16-bit instance format
        BinaryPrimitives.WriteUInt16LittleEndian(path.AsSpan(4), (ushort)instanceId);
        return path;
    }

    private static byte[] ElementCount(ushort count)
    {
        var data = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(data, count);
        return data;
    }

    private static byte[] BuildWriteData(ushort tagType, ushort elementCount, byte[] value)
    {
        var data = new byte[4 + value.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(data, tagType);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), elementCount);
        value.CopyTo(data.AsSpan(4));
        return data;
    }

    private async Task<TcpClient> ConnectAsync()
    {
        var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        return client;
    }

    private async Task<(byte generalStatus, byte[] data)> SendCipServiceAsync(
        NetworkStream stream, uint session, byte serviceCode, byte[] pathBytes, byte[] serviceData)
    {
        var mrRequest = new byte[2 + pathBytes.Length + serviceData.Length];
        mrRequest[0] = serviceCode;
        mrRequest[1] = (byte)(pathBytes.Length / 2);
        pathBytes.CopyTo(mrRequest.AsSpan(2));
        serviceData.CopyTo(mrRequest.AsSpan(2 + pathBytes.Length));

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
            SessionHandle = session,
        };

        var buf = new byte[EncapsulationHeader.Size + payload.Length];
        header.WriteTo(buf);
        payload.CopyTo(buf.AsSpan(EncapsulationHeader.Size));
        await stream.WriteAsync(buf);

        var headerBuf = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, headerBuf);
        var resp = EncapsulationHeader.Parse(headerBuf);

        var respPayload = new byte[resp.Length];
        await ReadExactAsync(stream, respPayload);

        var respCpf = CpfParser.Parse(respPayload.AsSpan(6));
        var mrResp = respCpf[1].Data.ToArray();

        byte generalStatus = mrResp[2];
        byte addStatusSize = mrResp[3];
        int dataOffset = 4 + addStatusSize * 2;
        return (generalStatus, mrResp.AsSpan(dataOffset).ToArray());
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
