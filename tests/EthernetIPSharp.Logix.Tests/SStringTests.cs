using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Logix.Tests;

/// <summary>
/// Tests for the atomic CIP SHORT_STRING tag type (0xDA).
///
/// The native representation is one length byte followed by up to 80
///   one-byte characters. 
///
/// NOTE: **It is not the ControlLogix STRING UDT representation
///   of LEN (DINT) plus DATA (SINT[82])**.
/// </summary>
public sealed class SStringTests : IAsyncLifetime
{
    private LogixDispatcher _logix = null!;
    private EipAdapter _adapter = null!;
    private CancellationTokenSource _cts = null!;
    private int _tcpPort;
    private Tag _asset = null!;

    public async Task InitializeAsync()
    {
        _cts = new CancellationTokenSource();
        _logix = new LogixDispatcher();
        _asset = _logix.Tags.AddTag("asset", LogixDataTypes.SHORT_STRING);
        _asset.WriteSString("ABC123");

        var identity = new IdentityInfo
        {
            VendorId = 1,
            DeviceType = 0x0E,
            ProductCode = 55,
            MajorRevision = 32,
            MinorRevision = 11,
            SerialNumber = 0xDEAD,
            ProductName = "EthernetIPSharp Logix SHORT_STRING Test",
        };

        _adapter = new EipAdapter(_logix, identity);
        _tcpPort = GetFreePort();

        await _adapter.ListenAsync(
            IPAddress.Loopback,
            _tcpPort,
            _cts.Token
        );
    }

    public async Task DisposeAsync()
    {
        _cts.Cancel();
        await _adapter.DisposeAsync();
        _cts.Dispose();
    }

    [Fact]
    public void NativeShortString_HasExpectedMetadataAndStorage()
    {
        Assert.Equal(LogixDataTypes.SHORT_STRING,           _asset.TagType);
        Assert.Equal(LogixDataTypes.SHORT_STRING,           _asset.SymbolType);
        Assert.Equal(LogixDataTypes.ShortStringStorageSize, _asset.ElementSize);
        Assert.Equal(LogixDataTypes.ShortStringStorageSize, _asset.DataSize);

        Assert.True(_asset.IsSString);
    }

    [Fact]
    public void NativeShortString_StoresLengthThenCharacters()
    {
        byte[] bytes = _asset.GetData().ToArray();

        Assert.Equal(81, bytes.Length);
        Assert.Equal(6, bytes[0]);
        Assert.Equal("ABC123", Encoding.ASCII.GetString(bytes, 1, bytes[0]));

        Assert.All(
            bytes.Skip(1 + 6),
            value => Assert.Equal(0, value)
        );
    }

    [Fact]
    public void NativeShortString_CanBeReadBackAsString()
    {
        Assert.Equal("ABC123", _asset.ReadSString());

        _asset.WriteSString("MOTOR-07");

        Assert.Equal("MOTOR-07", _asset.ReadSString());
    }

    [Fact]
    public void NativeShortString_RejectsValuesLongerThan80Characters()
    {
        string value = new('X', LogixDataTypes.ShortStringMaxLength + 1);

        Assert.Throws<ArgumentException>(() =>
            _asset.WriteSString(value));
    }

    [Fact]
    public void NativeShortString_RejectsNonAsciiValues()
    {
        Assert.Throws<ArgumentException>(() =>
            _asset.WriteSString("👻 MOTOR-4 👻"));
    }

    [Fact]
    public async Task ReadTag_BySymbolicName_ReturnsShortStringTypeAndPayload()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);

        NetworkStream stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var path = BuildSymbolicPath("asset");
        var requestData = new byte[] { 0x01, 0x00 };

        var (status, data) = await SendCipServiceAsync(
            stream,
            session,
            TagServices.ReadTag,
            path,
            requestData);

        Assert.Equal(0, status);
        Assert.Equal(
            2 + LogixDataTypes.ShortStringStorageSize,
            data.Length
        );

        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(data);
        Assert.Equal(LogixDataTypes.SHORT_STRING, tagType);

        byte length = data[2];
        Assert.Equal(6, length);
        Assert.Equal("ABC123", Encoding.ASCII.GetString(data, 3, length));
    }

    [Fact]
    public async Task WriteTag_BySymbolicName_UpdatesShortString()
    {
        const string newValue = "PUMP-42";
        byte[] payload = new byte[
            LogixDataTypes.ShortStringStorageSize];

        payload[0] = (byte)newValue.Length;
        Encoding.ASCII.GetBytes(newValue, payload.AsSpan(1));

        var writeData = new byte[4 + payload.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(
            writeData,
            LogixDataTypes.SHORT_STRING
        );
        BinaryPrimitives.WriteUInt16LittleEndian(
            writeData.AsSpan(2),
            1
        );
        payload.CopyTo(writeData, 4);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);

        NetworkStream stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var (status, _) = await SendCipServiceAsync(
            stream,
            session,
            TagServices.WriteTag,
            BuildSymbolicPath("asset"),
            writeData
        );

        Assert.Equal(0, status);
        Assert.Equal(newValue, _asset.ReadSString());
    }

    private static byte[] BuildSymbolicPath(string name)
    {
        int paddedLength = name.Length % 2 == 0
            ? name.Length
            : name.Length + 1;

        var path = new byte[2 + paddedLength];
        path[0] = 0x91; // ANSI Extended Symbolic Segment
        path[1] = checked((byte)name.Length);

        Encoding.ASCII.GetBytes(name, path.AsSpan(2));
        return path;
    }

    private static async Task<uint> RegisterSessionAsync(NetworkStream stream)
    {
        var request = new EncapsulationHeader
        {
            Command = EncapsulationCommand.RegisterSession,
            Length = 4,
        };

        var buffer = new byte[EncapsulationHeader.Size + 4];
        request.WriteTo(buffer);
        BinaryPrimitives.WriteUInt16LittleEndian(
            buffer.AsSpan(24), 1
        );

        await stream.WriteAsync(buffer);

        var response = new byte[EncapsulationHeader.Size + 4];
        await ReadExactAsync(stream, response);

        return EncapsulationHeader.Parse(response).SessionHandle;
    }

    private static async Task<(byte GeneralStatus, byte[] Data)> SendCipServiceAsync(
        NetworkStream stream,
        uint session,
        byte serviceCode,
        byte[] pathBytes,
        byte[] serviceData)
    {
        int pathSizeWords = pathBytes.Length / 2;
        var message = new byte[
            2 + pathBytes.Length + serviceData.Length];

        message[0] = serviceCode;
        message[1] = checked((byte)pathSizeWords);
        pathBytes.CopyTo(message, 2);
        serviceData.CopyTo(message, 2 + pathBytes.Length);

        var cpfBuffer = new byte[1024];
        var cpfItems = new CpfItem[]
        {
            new()
            {
                TypeId = CpfItemType.NullAddress,
                Data = ReadOnlyMemory<byte>.Empty,
            },
            new()
            {
                TypeId = CpfItemType.UnconnectedData,
                Data = message,
            },
        };

        int cpfLength = CpfParser.Write(cpfBuffer, cpfItems);
        var payload = new byte[6 + cpfLength];
        cpfBuffer.AsSpan(0, cpfLength).CopyTo(payload.AsSpan(6));

        var header = new EncapsulationHeader
        {
            Command = EncapsulationCommand.SendRRData,
            Length = checked((ushort)payload.Length),
            SessionHandle = session,
        };

        var request = new byte[
            EncapsulationHeader.Size + payload.Length];
        header.WriteTo(request);
        payload.CopyTo(request, EncapsulationHeader.Size);

        await stream.WriteAsync(request);

        var headerBytes = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, headerBytes);

        var responseHeader = EncapsulationHeader.Parse(headerBytes);
        var responsePayload = new byte[responseHeader.Length];
        await ReadExactAsync(stream, responsePayload);

        var responseCpf = CpfParser.Parse(responsePayload.AsSpan(6));
        byte[] messageResponse = responseCpf[1].Data.ToArray();

        byte generalStatus = messageResponse[2];
        byte additionalStatusSize = messageResponse[3];
        int dataOffset = 4 + additionalStatusSize * 2;
        byte[] data = messageResponse.AsSpan(dataOffset).ToArray();

        return (generalStatus, data);
    }

    private static async Task ReadExactAsync(
        NetworkStream stream,
        byte[] buffer)
    {
        int read = 0;

        while (read < buffer.Length)
        {
            int count = await stream.ReadAsync(buffer.AsMemory(read));

            if (count == 0)
                throw new IOException("Connection closed before the response was complete.");

            read += count;
        }
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}