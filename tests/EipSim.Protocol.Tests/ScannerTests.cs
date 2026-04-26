using System.Buffers.Binary;
using System.Net;
using EipSim.Cip;
using EipSim.Device;
using EipSim.Protocol;

namespace EipSim.Protocol.Tests;

/// <summary>
/// Loopback tests: start an adapter, connect a scanner to it, exchange data.
/// </summary>
[Collection("Scanner")]
public class ScannerTests : IAsyncLifetime
{
    private VirtualDevice _device = null!;
    private CancellationTokenSource _cts = null!;
    private int _tcpPort;
    private int _udpPort;

    public async Task InitializeAsync()
    {
        _cts = new CancellationTokenSource();
        var identity = new IdentityInfo
        {
            VendorId = 42, DeviceType = 0x0C, ProductCode = 1,
            MajorRevision = 1, MinorRevision = 0,
            SerialNumber = 0xABCD1234, ProductName = "LoopbackTarget",
        };

        _device = new VirtualDevice(identity, IPAddress.Loopback, "LoopbackTarget");
        _device.AddAssembly(100, 32, "T->O Produced");
        _device.AddAssembly(101, 32, "O->T Consumed");
        _device.AddAssembly(10, 0, "Config");

        // Pre-fill produced data
        var produced = _device.Assemblies.GetAssembly(100)!;
        produced.Write(0, 0xDEADBEEF);
        produced.Write(4, 42);

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

    [Fact]
    public async Task Scanner_ConnectsAndRegistersSession()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        Assert.True(scanner.IsConnected);
        Assert.NotEqual(0u, scanner.SessionHandle);
    }

    [Fact]
    public async Task Scanner_ReadsIdentityViaExplicitMessaging()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        // GetAttributeSingle: Identity (0x01), Instance 1, Attribute 1 (Vendor ID)
        var path = new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0x01 };
        var response = await scanner.SendExplicitAsync(0x0E, path, []);

        Assert.True(response.Status.IsSuccess);
        var vendorId = BinaryPrimitives.ReadUInt16LittleEndian(response.Data.Span);
        Assert.Equal(42, vendorId);
    }

    [Fact]
    public async Task Scanner_ForwardOpen_EstablishesIoConnection()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        var config = new ForwardOpenConfig
        {
            ConsumedAssembly = 101,  // O→T: scanner sends to target assembly 101
            ProducedAssembly = 100,  // T→O: target sends from assembly 100
            ConfigAssembly = 10,
            ConsumedSize = 32,
            ProducedSize = 32,
            Rpi = 20_000, // 20ms
        };

        await using var conn = await scanner.ForwardOpenAsync(config);

        Assert.True(conn.IsOpen);
        Assert.Single(_device.ConnectionManager.ActiveConnections);

        // Wait for some I/O exchange
        await Task.Delay(200);

        Assert.True(conn.IsOpen, "Connection should be open");
        Assert.True(conn.SendCount > 0, $"Expected O→T sends, got {conn.SendCount}. Target={conn.TargetEndpoint}");
        Assert.True(conn.ReceiveCount > 0, $"Expected T→O receives, got {conn.ReceiveCount}");
    }

    [Fact]
    public async Task Scanner_IoDataRoundTrip()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        var config = new ForwardOpenConfig
        {
            ConsumedAssembly = 101,
            ProducedAssembly = 100,
            ConfigAssembly = 10,
            ConsumedSize = 32,
            ProducedSize = 32,
            Rpi = 10_000,
        };

        await using var conn = await scanner.ForwardOpenAsync(config);

        // Write O→T data from scanner
        conn.Write(0, 12345);
        conn.Write(4, 67890);

        // Wait for target to receive it
        await Task.Delay(200);

        // Check target received the O→T data
        var consumed = _device.Assemblies.GetAssembly(101)!;
        // O→T data from scanner includes run/idle header (4 bytes), so our data starts at offset 0
        // after the VirtualDevice strips the header
        int targetVal0 = consumed.Read<int>(0);
        int targetVal1 = consumed.Read<int>(4);
        Assert.Equal(12345, targetVal0);
        Assert.Equal(67890, targetVal1);

        // Check scanner received T→O data from target
        // Target's produced assembly has 0xDEADBEEF at offset 0 and 42 at offset 4
        int scannerVal0 = conn.Read<int>(0);
        int scannerVal1 = conn.Read<int>(4);
        Assert.Equal(unchecked((int)0xDEADBEEF), scannerVal0);
        Assert.Equal(42, scannerVal1);
    }

    [Fact]
    public async Task Scanner_ForwardClose_CleansUp()
    {
        await using var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);

        var config = new ForwardOpenConfig
        {
            ConsumedAssembly = 101,
            ProducedAssembly = 100,
            ConfigAssembly = 10,
            ConsumedSize = 32,
            ProducedSize = 32,
            Rpi = 20_000,
        };

        var conn = await scanner.ForwardOpenAsync(config);
        Assert.Single(_device.ConnectionManager.ActiveConnections);

        await conn.CloseAsync();

        Assert.False(conn.IsOpen);
        Assert.Empty(_device.ConnectionManager.ActiveConnections);
    }

    [Fact]
    public async Task Scanner_DisconnectsCleanly()
    {
        var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, _tcpPort);
        Assert.True(scanner.IsConnected);

        await scanner.DisconnectAsync();
        Assert.False(scanner.IsConnected);
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
