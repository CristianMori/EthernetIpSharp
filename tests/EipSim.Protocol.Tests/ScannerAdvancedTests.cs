using System.Buffers.Binary;
using System.Net;
using EipSim.Cip;
using EipSim.Device;
using EipSim.Logix;
using EipSim.Protocol;

namespace EipSim.Protocol.Tests;

/// <summary>
/// Advanced scanner tests: multiple connections, error paths, explicit messaging,
/// Logix tag access via scanner, reconnection.
/// </summary>
[Collection("ScannerAdvanced")]
public class ScannerAdvancedTests : IAsyncLifetime
{
    private VirtualDevice _device = null!;
    private LogixDispatcher _logix = null!;
    private CancellationTokenSource _cts = null!;
    private int _tcpPort;
    private int _udpPort;

    public async Task InitializeAsync()
    {
        _cts = new CancellationTokenSource();

        _logix = new LogixDispatcher();
        _logix.Tags.AddTag("speed", LogixDataTypes.DINT).Write(0, 1500);
        _logix.Tags.AddTag("pressure", LogixDataTypes.REAL).Write(0, 25.5f);
        _logix.Tags.AddTag("counts", LogixDataTypes.INT, elementCount: 10);

        var identity = new IdentityInfo
        {
            VendorId = 99, DeviceType = 0x0E, ProductCode = 7,
            MajorRevision = 2, MinorRevision = 5,
            SerialNumber = 0xFACE, ProductName = "AdvancedTarget",
        };

        _device = new VirtualDevice(identity, IPAddress.Loopback,
            _logix, new AssemblyObject(), new EipSim.Connections.ConnectionManagerObject(),
            "AdvancedTarget");

        _device.AddAssembly(100, 64, "Produced");
        _device.AddAssembly(101, 64, "Consumed");
        _device.AddAssembly(10, 0, "Config");

        // Fill produced data
        var produced = _device.Assemblies.GetAssembly(100)!;
        for (int i = 0; i < 16; i++)
            produced.Write(i * 4, (i + 1) * 100);

        _tcpPort = GetFreePort();
        _udpPort = GetFreePort();
        await _device.StartAsync(_tcpPort, _udpPort, _cts.Token);
    }

    public async Task DisposeAsync()
    {
        _cts.Cancel();
        await _device.DisposeAsync();
        _cts.Dispose();
    }

    // --- Explicit Messaging ---

    [Fact]
    public async Task Scanner_GetAttributeAll_ReturnsIdentityData()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        // GetAttributeAll on Identity class 0x01, instance 1
        var path = new byte[] { 0x20, 0x01, 0x24, 0x01 };
        var response = await scanner.SendExplicitAsync(0x01, path, []);

        Assert.True(response.Status.IsSuccess);
        Assert.True(response.Data.Length > 10); // vendor + device type + product code + revision + ...

        // Parse: vendor ID (2) + device type (2) + product code (2)
        var data = response.Data.ToArray();
        ushort vendorId = BinaryPrimitives.ReadUInt16LittleEndian(data);
        ushort deviceType = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2));
        Assert.Equal(99, vendorId);
        Assert.Equal(0x0E, deviceType);
    }

    [Fact]
    public async Task Scanner_ReadMultipleAttributes()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        // Read Vendor ID (attr 1)
        var path1 = new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0x01 };
        var resp1 = await scanner.SendExplicitAsync(0x0E, path1, []);
        Assert.True(resp1.Status.IsSuccess);
        Assert.Equal(99, BinaryPrimitives.ReadUInt16LittleEndian(resp1.Data.Span));

        // Read Serial Number (attr 6)
        var path6 = new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0x06 };
        var resp6 = await scanner.SendExplicitAsync(0x0E, path6, []);
        Assert.True(resp6.Status.IsSuccess);
        Assert.Equal(0xFACEu, BinaryPrimitives.ReadUInt32LittleEndian(resp6.Data.Span));

        // Read Product Name (attr 7) — SHORT_STRING
        var path7 = new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0x07 };
        var resp7 = await scanner.SendExplicitAsync(0x0E, path7, []);
        Assert.True(resp7.Status.IsSuccess);
        byte nameLen = resp7.Data.Span[0];
        string name = System.Text.Encoding.ASCII.GetString(resp7.Data.Span.Slice(1, nameLen));
        Assert.Equal("AdvancedTarget", name);
    }

    [Fact]
    public async Task Scanner_InvalidPath_ReturnsError()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        // Read from non-existent class 0xFF
        var path = new byte[] { 0x20, 0xFF, 0x24, 0x01, 0x30, 0x01 };
        var response = await scanner.SendExplicitAsync(0x0E, path, []);

        Assert.False(response.Status.IsSuccess);
        Assert.Equal(0x05, response.Status.GeneralStatus); // Path destination unknown
    }

    [Fact]
    public async Task Scanner_InvalidAttribute_ReturnsError()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        // Read non-existent attribute 99 from Identity
        var path = new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0x63 };
        var response = await scanner.SendExplicitAsync(0x0E, path, []);

        Assert.False(response.Status.IsSuccess);
    }

    // --- Logix Tag Access via Scanner ---

    [Fact]
    public async Task Scanner_ReadTag_BySymbolicName()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        // Read Tag "speed" via symbolic segment
        var path = BuildSymbolicPath("speed");
        var reqData = new byte[] { 0x01, 0x00 }; // 1 element
        var response = await scanner.SendExplicitAsync(0x4C, path, reqData);

        Assert.True(response.Status.IsSuccess);
        var data = response.Data.ToArray();
        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(data);
        Assert.Equal(LogixDataTypes.DINT, tagType);
        int value = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(2));
        Assert.Equal(1500, value);
    }

    [Fact]
    public async Task Scanner_WriteTag_ThenReadBack()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        // Write 9999 to "speed"
        var writePath = BuildSymbolicPath("speed");
        var writeData = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(writeData, LogixDataTypes.DINT);
        BinaryPrimitives.WriteUInt16LittleEndian(writeData.AsSpan(2), 1);
        BinaryPrimitives.WriteInt32LittleEndian(writeData.AsSpan(4), 9999);
        var writeResp = await scanner.SendExplicitAsync(0x4D, writePath, writeData);
        Assert.True(writeResp.Status.IsSuccess);

        // Read it back
        var readPath = BuildSymbolicPath("speed");
        var readResp = await scanner.SendExplicitAsync(0x4C, readPath, new byte[] { 0x01, 0x00 });
        Assert.True(readResp.Status.IsSuccess);
        int value = BinaryPrimitives.ReadInt32LittleEndian(readResp.Data.Span.Slice(2));
        Assert.Equal(9999, value);
    }

    [Fact]
    public async Task Scanner_ReadTag_Float()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        var path = BuildSymbolicPath("pressure");
        var response = await scanner.SendExplicitAsync(0x4C, path, new byte[] { 0x01, 0x00 });

        Assert.True(response.Status.IsSuccess);
        var data = response.Data.ToArray();
        Assert.Equal(LogixDataTypes.REAL, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(25.5f, BinaryPrimitives.ReadSingleLittleEndian(data.AsSpan(2)));
    }

    [Fact]
    public async Task Scanner_ReadTag_NonExistent_ReturnsError()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        var path = BuildSymbolicPath("doesnotexist");
        var response = await scanner.SendExplicitAsync(0x4C, path, new byte[] { 0x01, 0x00 });

        Assert.False(response.Status.IsSuccess);
        Assert.Equal(0x05, response.Status.GeneralStatus);
    }

    // --- I/O Connection Edge Cases ---

    [Fact]
    public async Task Scanner_ForwardOpen_InvalidAssembly_Throws()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        var config = new ForwardOpenConfig
        {
            ConsumedAssembly = 999, // Does not exist
            ProducedAssembly = 100,
            ConfigAssembly = 10,
            ConsumedSize = 64,
            ProducedSize = 64,
            Rpi = 20_000,
        };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => scanner.ForwardOpenAsync(config));
    }

    [Fact]
    public async Task Scanner_IoConnection_DataChangesReflected()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        var config = new ForwardOpenConfig
        {
            ConsumedAssembly = 101,
            ProducedAssembly = 100,
            ConfigAssembly = 10,
            ConsumedSize = 64,
            ProducedSize = 64,
            Rpi = 10_000,
        };

        await using var conn = await scanner.ForwardOpenAsync(config);

        // Write different values at different times
        conn.Write(0, 111);
        await Task.Delay(100);

        var consumed = _device.Assemblies.GetAssembly(101)!;
        Assert.Equal(111, consumed.Read<int>(0));

        conn.Write(0, 222);
        await Task.Delay(100);
        Assert.Equal(222, consumed.Read<int>(0));
    }

    [Fact]
    public async Task Scanner_IoConnection_DataReceivedEventFires()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        var config = new ForwardOpenConfig
        {
            ConsumedAssembly = 101,
            ProducedAssembly = 100,
            ConfigAssembly = 10,
            ConsumedSize = 64,
            ProducedSize = 64,
            Rpi = 10_000,
        };

        int eventCount = 0;
        await using var conn = await scanner.ForwardOpenAsync(config);
        conn.DataReceived += _ => Interlocked.Increment(ref eventCount);

        await Task.Delay(200);

        Assert.True(eventCount > 5, $"Expected DataReceived events, got {eventCount}");
    }

    [Fact]
    public async Task Scanner_MultipleSequentialConnections()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        var config = new ForwardOpenConfig
        {
            ConsumedAssembly = 101,
            ProducedAssembly = 100,
            ConfigAssembly = 10,
            ConsumedSize = 64,
            ProducedSize = 64,
            Rpi = 20_000,
        };

        // Open, exchange, close — twice
        for (int round = 0; round < 2; round++)
        {
            var conn = await scanner.ForwardOpenAsync(config);
            Assert.True(conn.IsOpen);
            conn.Write(0, round + 1);
            await Task.Delay(100);
            Assert.True(conn.SendCount > 0);
            await conn.CloseAsync();
            Assert.False(conn.IsOpen);
            Assert.Empty(_device.ConnectionManager.ActiveConnections);
        }
    }

    [Fact]
    public async Task Scanner_MultipleSessionsToSameTarget()
    {
        await using var scanner1 = new EipScanner();
        await using var scanner2 = new EipScanner();

        await scanner1.ConnectAsync(IPAddress.Loopback, _tcpPort);
        await scanner2.ConnectAsync(IPAddress.Loopback, _tcpPort);

        Assert.True(scanner1.IsConnected);
        Assert.True(scanner2.IsConnected);
        Assert.NotEqual(scanner1.SessionHandle, scanner2.SessionHandle);

        // Both can read identity
        var path = new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0x01 };
        var resp1 = await scanner1.SendExplicitAsync(0x0E, path, []);
        var resp2 = await scanner2.SendExplicitAsync(0x0E, path, []);

        Assert.True(resp1.Status.IsSuccess);
        Assert.True(resp2.Status.IsSuccess);
        Assert.Equal(99, BinaryPrimitives.ReadUInt16LittleEndian(resp1.Data.Span));
        Assert.Equal(99, BinaryPrimitives.ReadUInt16LittleEndian(resp2.Data.Span));
    }

    // --- Helpers ---

    private static byte[] BuildSymbolicPath(string name)
    {
        int padded = name.Length % 2 != 0 ? name.Length + 1 : name.Length;
        var path = new byte[2 + padded];
        path[0] = 0x91;
        path[1] = (byte)name.Length;
        System.Text.Encoding.ASCII.GetBytes(name, path.AsSpan(2));
        return path;
    }

    private static int GetFreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
