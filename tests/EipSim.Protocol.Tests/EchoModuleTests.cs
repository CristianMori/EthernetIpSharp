using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EipSim.Cip;
using EipSim.Connections;
using EipSim.Device;
using EipSim.Protocol;

namespace EipSim.Protocol.Tests;

/// <summary>
/// End-to-end test emulating the Studio 5000 Generic Ethernet Module "test" config:
///   Type: ETHERNET-MODULE Generic Ethernet Module
///   IP: 192.168.204.2 (we use loopback)
///   Comm Format: Data - DINT
///   Input (T→O):  Assembly 100, 125 DINTs = 500 bytes
///   Output (O→T): Assembly 101, 124 DINTs = 496 bytes
///   Config:       Assembly 10,  0 bytes
/// </summary>
public class EchoModuleTests : IAsyncLifetime
{
    private const int ProducedInstance = 100;  // Input in Studio = T→O = what device sends to PLC
    private const int ConsumedInstance = 101;  // Output in Studio = O→T = what PLC sends to device
    private const int ConfigInstance = 10;
    private const int ProducedSizeDints = 125; // 500 bytes
    private const int ConsumedSizeDints = 124; // 496 bytes
    private const int ProducedSizeBytes = ProducedSizeDints * 4; // 500
    private const int ConsumedSizeBytes = ConsumedSizeDints * 4; // 496

    private VirtualDevice _device = null!;
    private CancellationTokenSource _cts = null!;
    private int _tcpPort;
    private int _udpPort;

    public async Task InitializeAsync()
    {
        _cts = new CancellationTokenSource();
        var identity = new IdentityInfo
        {
            VendorId = 1,          // Rockwell
            DeviceType = 0x0C,     // Communications Adapter
            ProductCode = 1,
            MajorRevision = 1,
            MinorRevision = 0,
            SerialNumber = 0xC0FFEE,
            ProductName = "EipSim Echo Module",
        };

        _device = new VirtualDevice(identity, IPAddress.Loopback, "test");
        _device.AddAssembly(ProducedInstance, ProducedSizeBytes, "T->O Input");
        _device.AddAssembly(ConsumedInstance, ConsumedSizeBytes, "O->T Output");
        _device.AddAssembly(ConfigInstance, 0, "Configuration");

        // Pre-fill produced data with a recognizable pattern
        var produced = _device.Assemblies.GetAssembly(ProducedInstance)!;
        for (int i = 0; i < ProducedSizeDints; i++)
            produced.Write(i * 4, i + 1); // DINT[0]=1, DINT[1]=2, ..., DINT[124]=125

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
    public async Task ListIdentity_ReturnsEchoModule()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();

        var header = new EncapsulationHeader { Command = EncapsulationCommand.ListIdentity };
        var buf = new byte[EncapsulationHeader.Size];
        header.WriteTo(buf);
        await stream.WriteAsync(buf);

        var respBuf = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, respBuf);
        var resp = EncapsulationHeader.Parse(respBuf);
        Assert.Equal(0u, resp.Status);

        var payload = new byte[resp.Length];
        await ReadExactAsync(stream, payload);
        var items = CpfParser.Parse(payload);
        Assert.Single(items);
        Assert.Equal(CpfItemType.CipIdentity, items[0].TypeId);
    }

    [Fact]
    public async Task ForwardOpen_WithStudioConfig_EstablishesConnection()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Build Forward Open matching Studio 5000 config exactly
        var connPath = new byte[]
        {
            0x20, 0x04,       // Class: Assembly (0x04)
            0x24, ConfigInstance,  // Instance: 10 (config)
            0x2C, ConsumedInstance, // Connection Point: 101 (O→T)
            0x2C, ProducedInstance, // Connection Point: 100 (T→O)
        };

        // Connection sizes include 2-byte sequence count for Class 1
        ushort otSize = ConsumedSizeBytes + 2;  // 498 (O→T: PLC sends to us)
        ushort toSize = ProducedSizeBytes + 2;  // 502 (T→O: we send to PLC)

        // Network params: point-to-point, fixed size
        ushort otParams = (ushort)(0x4000 | (otSize & 0x01FF));
        ushort toParams = (ushort)(0x4000 | (toSize & 0x01FF));

        uint rpi = 10000; // 10ms RPI

        var fwdOpen = new byte[36 + connPath.Length];
        int off = 0;
        fwdOpen[off++] = 0x0A; // Priority/Time_tick
        fwdOpen[off++] = 0xFA; // Timeout_ticks
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), 0xAAAA0001); off += 4; // OT conn ID
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), 0x00CAFE01); off += 4; // TO conn ID (originator chooses)
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpen.AsSpan(off), 100); off += 2; // Connection Serial
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpen.AsSpan(off), 1); off += 2; // Originator Vendor (Rockwell)
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), 0xC0FFEE); off += 4; // Originator Serial
        fwdOpen[off++] = 2; // Timeout multiplier (×16)
        off += 3; // Reserved
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), rpi); off += 4; // OT RPI
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpen.AsSpan(off), otParams); off += 2; // OT params
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), rpi); off += 4; // TO RPI
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpen.AsSpan(off), toParams); off += 2; // TO params
        fwdOpen[off++] = 0x01; // Transport: Class 1, cyclic, server
        fwdOpen[off++] = (byte)(connPath.Length / 2); // Path size in words
        connPath.CopyTo(fwdOpen.AsSpan(off));

        // Wrap as MR request to Connection Manager (Class 0x06, Instance 1)
        var mrRequest = new byte[6 + fwdOpen.Length];
        mrRequest[0] = 0x54; // Forward Open
        mrRequest[1] = 0x02; // Path: 2 words
        mrRequest[2] = 0x20; mrRequest[3] = 0x06; // Class 0x06
        mrRequest[4] = 0x24; mrRequest[5] = 0x01; // Instance 1
        fwdOpen.CopyTo(mrRequest.AsSpan(6));

        var (status, data) = await SendUcmmAsync(stream, session, mrRequest);

        Assert.Equal(0, status);

        // Parse Forward Open response
        uint respOtConnId = BinaryPrimitives.ReadUInt32LittleEndian(data);
        uint respToConnId = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4));
        ushort respSerial = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(8));
        ushort respVendor = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(10));
        uint respOrigSerial = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(12));

        Assert.NotEqual(0u, respOtConnId);          // Target-assigned (non-zero)
        Assert.NotEqual(0u, respToConnId);           // From request or target-assigned
        Assert.Equal(100, respSerial);            // Echoed
        Assert.Equal(1, respVendor);              // Echoed
        Assert.Equal(0xC0FFEEu, respOrigSerial);  // Echoed

        // Verify connection state
        Assert.Single(_device.ConnectionManager.ActiveConnections);
        var conn = _device.ConnectionManager.ActiveConnections.First();
        Assert.Equal(ConsumedInstance, (int)conn.ConsumedAssemblyInstance);
        Assert.Equal(ProducedInstance, (int)conn.ProducedAssemblyInstance);
        Assert.Equal(rpi, conn.OtoTRpi);
        Assert.Equal(rpi, conn.TtoORpi);
        Assert.Equal(TransportClass.Class1, conn.TransportClass);
        Assert.Equal(2, conn.TimeoutMultiplier); // ×16

        // Clean up: Forward Close
        var closeData = new byte[12];
        off = 0;
        closeData[off++] = 0x0A; closeData[off++] = 0xFA;
        BinaryPrimitives.WriteUInt16LittleEndian(closeData.AsSpan(off), 100); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(closeData.AsSpan(off), 1); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(closeData.AsSpan(off), 0xC0FFEE); off += 4;
        closeData[off++] = 0; closeData[off++] = 0;

        var closeMr = new byte[6 + closeData.Length];
        closeMr[0] = 0x4E; closeMr[1] = 0x02;
        closeMr[2] = 0x20; closeMr[3] = 0x06;
        closeMr[4] = 0x24; closeMr[5] = 0x01;
        closeData.CopyTo(closeMr.AsSpan(6));

        var (closeStatus, _) = await SendUcmmAsync(stream, session, closeMr);
        Assert.Equal(0, closeStatus);
        Assert.Empty(_device.ConnectionManager.ActiveConnections);
    }

    [Fact]
    public async Task ForwardOpen_WithLogixEmulateWrapper_AlsoWorks()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Same path as above but with Logix Emulate wrapper prefix
        var realPath = new byte[]
        {
            0x20, 0x04,
            0x24, ConfigInstance,
            0x2C, ConsumedInstance,
            0x2C, ProducedInstance,
        };

        // Prepend the Logix Emulate wrapper: 21 00 FC 04 2C 01
        var wrappedPath = new byte[6 + realPath.Length];
        wrappedPath[0] = 0x21; wrappedPath[1] = 0x00; // 16-bit class
        wrappedPath[2] = 0xFC; wrappedPath[3] = 0x04; // class 0x04FC
        wrappedPath[4] = 0x2C; wrappedPath[5] = 0x01; // connection point 1
        realPath.CopyTo(wrappedPath.AsSpan(6));

        ushort otSize = ConsumedSizeBytes + 2;
        ushort toSize = ProducedSizeBytes + 2;
        ushort otParams = (ushort)(0x4000 | (otSize & 0x01FF));
        ushort toParams = (ushort)(0x4000 | (toSize & 0x01FF));

        var fwdOpen = new byte[36 + wrappedPath.Length];
        int off = 0;
        fwdOpen[off++] = 0x0A; fwdOpen[off++] = 0xFA;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), 0xBBBB0001); off += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), 0x00CAFE02); off += 4; // TO conn ID
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpen.AsSpan(off), 200); off += 2; // Different serial
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpen.AsSpan(off), 1); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), 0xBEEF); off += 4;
        fwdOpen[off++] = 0; off += 3;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), 20000); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpen.AsSpan(off), otParams); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpen.AsSpan(off), 20000); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpen.AsSpan(off), toParams); off += 2;
        fwdOpen[off++] = 0x01;
        fwdOpen[off++] = (byte)(wrappedPath.Length / 2);
        wrappedPath.CopyTo(fwdOpen.AsSpan(off));

        var mrRequest = new byte[6 + fwdOpen.Length];
        mrRequest[0] = 0x54; mrRequest[1] = 0x02;
        mrRequest[2] = 0x20; mrRequest[3] = 0x06;
        mrRequest[4] = 0x24; mrRequest[5] = 0x01;
        fwdOpen.CopyTo(mrRequest.AsSpan(6));

        var (status, data) = await SendUcmmAsync(stream, session, mrRequest);

        // Must succeed — wrapper stripped, same assemblies resolved
        Assert.Equal(0, status);
        Assert.NotEqual(0u, BinaryPrimitives.ReadUInt32LittleEndian(data));       // OT conn ID assigned by target
        Assert.NotEqual(0u, BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4))); // TO conn ID

        var conn = _device.ConnectionManager.ActiveConnections.First();
        Assert.Equal(ConsumedInstance, (int)conn.ConsumedAssemblyInstance);
        Assert.Equal(ProducedInstance, (int)conn.ProducedAssemblyInstance);
    }

    [Fact]
    public async Task ProducedData_IsReadableViaGetAttributeSingle()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Read Assembly 100 attribute 3 (Data) via GetAttributeSingle
        var mrRequest = new byte[]
        {
            0x0E,       // GetAttributeSingle
            0x03,       // Path: 3 words
            0x20, 0x04, // Class: Assembly (0x04)
            0x24, ProducedInstance, // Instance 100
            0x30, 0x03, // Attribute 3 (Data)
        };

        var (status, data) = await SendUcmmAsync(stream, session, mrRequest);
        Assert.Equal(0, status);
        Assert.Equal(ProducedSizeBytes, data.Length);

        // Verify pattern: DINT[0]=1, DINT[1]=2
        Assert.Equal(1, BinaryPrimitives.ReadInt32LittleEndian(data));
        Assert.Equal(2, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4)));
        Assert.Equal(125, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(496))); // Last DINT
    }

    // --- Helpers ---

    private async Task<(byte generalStatus, byte[] data)> SendUcmmAsync(
        NetworkStream stream, uint session, byte[] mrRequest)
    {
        var cpfBuf = new byte[2048];
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
            SessionHandle = session,
        };
        var buf = new byte[EncapsulationHeader.Size + payload.Length];
        header.WriteTo(buf);
        payload.CopyTo(buf.AsSpan(EncapsulationHeader.Size));
        await stream.WriteAsync(buf);

        var respHdr = new byte[EncapsulationHeader.Size];
        await ReadExactAsync(stream, respHdr);
        var resp = EncapsulationHeader.Parse(respHdr);

        var respPayload = new byte[resp.Length];
        await ReadExactAsync(stream, respPayload);

        var cpf = CpfParser.Parse(respPayload.AsSpan(6));
        var mr = cpf[1].Data.ToArray();
        byte gs = mr[2];
        byte addSize = mr[3];
        int dataOff = 4 + addSize * 2;
        return (gs, mr.AsSpan(dataOff).ToArray());
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
