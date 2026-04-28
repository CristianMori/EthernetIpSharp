using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using EipSim.Cip;
using EipSim.Logix;
using EipSim.Protocol;

namespace EipSim.Logix.Tests;

/// <summary>
/// Advanced Logix tests: templates, Multiple Service Packet, fragmented read, tag browsing.
/// End-to-end over TCP with LogixDispatcher.
/// </summary>
public class AdvancedLogixTests : IAsyncLifetime
{
    private LogixDispatcher _logix = null!;
    private EipAdapter _adapter = null!;
    private CancellationTokenSource _cts = null!;
    private int _tcpPort;
    private TemplateDefinition _machineTemplate = null!;

    public async Task InitializeAsync()
    {
        _cts = new CancellationTokenSource();
        _logix = new LogixDispatcher();

        // Atomic tags
        _logix.Tags.AddTag("rate", LogixDataTypes.DINT).Write(0, 42);
        _logix.Tags.AddTag("speed", LogixDataTypes.REAL).Write(0, 3.14f);

        // Large array for fragmented test
        var bigArray = _logix.Tags.AddTag("bigdata", LogixDataTypes.SINT, elementCount: 1000);
        var initData = new byte[1000];
        for (int i = 0; i < 1000; i++)
            initData[i] = (byte)(i & 0xFF);
        bigArray.SetData(initData);

        // UDT
        _machineTemplate = _logix.Tags.AddTemplate("MachineData",
            new TemplateMember("velocity", LogixDataTypes.REAL),
            new TemplateMember("position", LogixDataTypes.DINT),
            new TemplateMember("status", LogixDataTypes.INT));
        var machine = _logix.Tags.AddTag("machine1", _machineTemplate);
        machine.Write(0, 1.5f);   // velocity
        machine.Write(4, 1000);   // position
        machine.Write(8, (short)1); // status

        // Sync CIP instances so template/symbol instances are created
        _logix.SyncCipInstances();

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

    // --- Template Tests ---

    [Fact]
    public async Task TemplateGetAttributeList_ReturnsStructInfo()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Get_Attribute_List (0x03) on Template class 0x6C, instance = _machineTemplate.InstanceId
        // Request attrs: 1 (handle), 2 (member count), 4 (def size), 5 (struct size)
        var path = new byte[]
        {
            0x20, 0x6C, // Class 0x6C
            0x25, 0x00, // Instance (16-bit format)
            (byte)(_machineTemplate.InstanceId & 0xFF),
            (byte)((_machineTemplate.InstanceId >> 8) & 0xFF),
        };

        var reqData = new byte[10];
        BinaryPrimitives.WriteUInt16LittleEndian(reqData, 4); // 4 attributes
        BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(2), 1); // attr 1
        BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(4), 2); // attr 2
        BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(6), 4); // attr 4
        BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(8), 5); // attr 5

        var (status, data) = await SendCipServiceAsync(stream, session, 0x03, path, reqData);

        Assert.Equal(0, status);
        Assert.True(data.Length > 0);

        // Parse response: count + [attr_id, status, data]...
        ushort count = BinaryPrimitives.ReadUInt16LittleEndian(data);
        Assert.Equal(4, count);

        int off = 2;
        // Attr 1: Structure Handle
        ushort attr1Id = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        ushort attr1Status = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        Assert.Equal(1, attr1Id);
        Assert.Equal(0, attr1Status);
        ushort structHandle = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        Assert.Equal(_machineTemplate.StructureHandle, structHandle);

        // Attr 2: Member Count
        ushort attr2Id = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        ushort attr2Status = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        Assert.Equal(2, attr2Id);
        Assert.Equal(0, attr2Status);
        ushort memberCount = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        Assert.Equal(3, memberCount); // velocity, position, status

        // Attr 4: Definition Size (UDINT)
        ushort attr4Id = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        ushort attr4Status = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        Assert.Equal(4, attr4Id);
        Assert.Equal(0, attr4Status);
        uint defSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(off)); off += 4;
        Assert.True(defSize > 0, "Definition size should be positive");

        // Attr 5: Structure Size (UDINT)
        ushort attr5Id = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        ushort attr5Status = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
        Assert.Equal(5, attr5Id);
        Assert.Equal(0, attr5Status);
        uint structSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(off)); off += 4;
        Assert.Equal(_machineTemplate.StructureSize, structSize);
    }

    [Fact]
    public async Task TemplateRead_ReturnsMemberInfo()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Template Read (0x4C) on class 0x6C, instance = template ID
        var path = new byte[]
        {
            0x20, 0x6C,
            0x25, 0x00,
            (byte)(_machineTemplate.InstanceId & 0xFF),
            (byte)((_machineTemplate.InstanceId >> 8) & 0xFF),
        };

        // Request: offset=0, bytes_to_read=256
        var reqData = new byte[6];
        BinaryPrimitives.WriteUInt32LittleEndian(reqData, 0); // offset
        BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(4), 256); // bytes to read

        var (status, data) = await SendCipServiceAsync(stream, session, 0x4C, path, reqData);

        Assert.Equal(0, status);
        Assert.True(data.Length > 0);

        // Parse member info: 3 members × 8 bytes each = 24 bytes, then names
        // Member 0: velocity (REAL, offset 0)
        uint member0TypeInfo = BinaryPrimitives.ReadUInt32LittleEndian(data);
        ushort member0Type = (ushort)(member0TypeInfo >> 16);
        Assert.Equal(LogixDataTypes.REAL, member0Type);
        uint member0Offset = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4));
        Assert.Equal(0u, member0Offset);

        // Member 1: position (DINT, offset 4)
        uint member1TypeInfo = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(8));
        ushort member1Type = (ushort)(member1TypeInfo >> 16);
        Assert.Equal(LogixDataTypes.DINT, member1Type);
        uint member1Offset = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(12));
        Assert.Equal(4u, member1Offset);

        // Member 2: status (INT, offset 8)
        uint member2TypeInfo = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(16));
        ushort member2Type = (ushort)(member2TypeInfo >> 16);
        Assert.Equal(LogixDataTypes.INT, member2Type);
        uint member2Offset = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(20));
        Assert.Equal(8u, member2Offset);

        // After 24 bytes of member info, names are null-terminated strings
        int namesStart = 3 * 8;

        // Parse null-terminated names: template name, then member names in order
        var names = new List<string>();
        int pos = namesStart;
        while (pos < data.Length)
        {
            int end = Array.IndexOf(data, (byte)0, pos);
            if (end < 0) break;
            if (end > pos) names.Add(Encoding.ASCII.GetString(data.AsSpan(pos, end - pos)));
            pos = end + 1;
        }

        Assert.True(names.Count >= 4, $"Expected 4 names (template + 3 members), got {names.Count}: [{string.Join(", ", names)}]");
        Assert.Equal("MachineData", names[0]); // Template name first
        Assert.Equal("velocity", names[1]);
        Assert.Equal("position", names[2]);
        Assert.Equal("status", names[3]);
    }

    // --- Multiple Service Packet Tests ---

    [Fact]
    public async Task MultiServicePacket_ReadsTwoTags()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Multiple Service Packet: path to Message Router (class 2, instance 1)
        var mrPath = new byte[] { 0x20, 0x02, 0x24, 0x01 };

        // Sub-request 1: Read Tag "rate" (1 element)
        var sub1Path = BuildSymbolicPath("rate");
        var sub1Data = new byte[] { 0x01, 0x00 }; // 1 element
        var sub1 = BuildMrRequest(0x4C, sub1Path, sub1Data);

        // Sub-request 2: Read Tag "speed" (1 element)
        var sub2Path = BuildSymbolicPath("speed");
        var sub2Data = new byte[] { 0x01, 0x00 };
        var sub2 = BuildMrRequest(0x4C, sub2Path, sub2Data);

        // Build multi-service request data
        ushort serviceCount = 2;
        int headerSize = 2 + serviceCount * 2; // count + offset table
        ushort offset1 = (ushort)headerSize;
        ushort offset2 = (ushort)(offset1 + sub1.Length);

        var multiReqData = new byte[headerSize + sub1.Length + sub2.Length];
        int off = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(multiReqData.AsSpan(off), serviceCount); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(multiReqData.AsSpan(off), offset1); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(multiReqData.AsSpan(off), offset2); off += 2;
        sub1.CopyTo(multiReqData.AsSpan(off)); off += sub1.Length;
        sub2.CopyTo(multiReqData.AsSpan(off));

        var (status, data) = await SendCipServiceAsync(stream, session, 0x0A, mrPath, multiReqData);

        Assert.Equal(0, status); // Overall success

        // Parse multi-service response
        ushort respCount = BinaryPrimitives.ReadUInt16LittleEndian(data);
        Assert.Equal(2, respCount);

        // Read response offsets
        ushort respOff1 = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2));
        ushort respOff2 = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(4));

        // Sub-response 1: Read Tag reply for "rate"
        byte resp1Service = data[respOff1];
        Assert.Equal(0x4C | 0x80, resp1Service);
        byte resp1Status = data[respOff1 + 2];
        Assert.Equal(0, resp1Status); // Success
        // Data: tag_type (DINT=0xC4) + value (42)
        ushort resp1TagType = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(respOff1 + 4));
        Assert.Equal(LogixDataTypes.DINT, resp1TagType);
        int resp1Value = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(respOff1 + 6));
        Assert.Equal(42, resp1Value);

        // Verify offsets are ordered (resp2 starts after resp1)
        Assert.True(respOff2 > respOff1, "Response offsets must be ordered");

        // Sub-response 2: Read Tag reply for "speed"
        byte resp2Service = data[respOff2];
        Assert.Equal(0x4C | 0x80, resp2Service); // Read Tag reply
        byte resp2Status = data[respOff2 + 2];
        Assert.Equal(0, resp2Status);
        ushort resp2TagType = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(respOff2 + 4));
        Assert.Equal(LogixDataTypes.REAL, resp2TagType);
        float resp2Value = BinaryPrimitives.ReadSingleLittleEndian(data.AsSpan(respOff2 + 6));
        Assert.Equal(3.14f, resp2Value);
    }

    // --- Fragmented Read Test ---

    [Fact]
    public async Task ReadTagFragmented_ReadsLargeArray()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        var path = BuildSymbolicPath("bigdata");

        // First request: offset=0, 1000 elements
        var reqData = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(reqData, 1000); // element count
        BinaryPrimitives.WriteUInt32LittleEndian(reqData.AsSpan(2), 0); // byte offset

        var (status, data) = await SendCipServiceAsync(stream, session, 0x52, path, reqData);

        // Should get status 0x06 (more data) since 1000 SINTs > max reply size
        Assert.Equal(0x06, status);
        Assert.True(data.Length > 2); // at least tag_type + some data

        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(data);
        Assert.Equal(LogixDataTypes.SINT, tagType);

        int firstChunkBytes = data.Length - 2;
        Assert.True(firstChunkBytes > 0 && firstChunkBytes < 1000);

        // Verify data values match
        for (int i = 0; i < firstChunkBytes; i++)
            Assert.Equal((byte)(i & 0xFF), data[2 + i]);

        // Second request: continue from where we left off
        var reqData2 = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(reqData2, 1000);
        BinaryPrimitives.WriteUInt32LittleEndian(reqData2.AsSpan(2), (uint)firstChunkBytes);

        var (status2, data2) = await SendCipServiceAsync(stream, session, 0x52, path, reqData2);

        // Could be 0x06 or 0x00 depending on remaining size
        Assert.True(status2 == 0 || status2 == 0x06);
        Assert.True(data2.Length > 2);

        // Verify continuity
        for (int i = 0; i < data2.Length - 2; i++)
            Assert.Equal((byte)((firstChunkBytes + i) & 0xFF), data2[2 + i]);
    }

    // --- Tag Browsing Test ---

    [Fact]
    public async Task GetInstanceAttributeList_ReturnsTags()
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _tcpPort);
        var stream = client.GetStream();
        uint session = await RegisterSessionAsync(stream);

        // Collect all tags across paginated responses
        var foundNames = new List<string>();
        uint startInstance = 0;

        while (true)
        {
            var path = new byte[6];
            path[0] = 0x20; path[1] = 0x6B; // Class 0x6B
            path[2] = 0x25; path[3] = 0x00; // 16-bit instance
            BinaryPrimitives.WriteUInt16LittleEndian(path.AsSpan(4), (ushort)startInstance);

            var reqData = new byte[6];
            BinaryPrimitives.WriteUInt16LittleEndian(reqData, 2);
            BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(2), 1); // name
            BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(4), 2); // type

            var (status, data) = await SendCipServiceAsync(stream, session, 0x55, path, reqData);
            Assert.True(status == 0 || status == 0x06, $"Unexpected status 0x{status:X2}");

            // Parse all entries in this response
            int off = 0;
            uint lastInstanceId = 0;
            while (off + 6 < data.Length)
            {
                uint instId = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(off)); off += 4;
                ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
                if (off + nameLen + 2 > data.Length) break;
                string name = Encoding.ASCII.GetString(data.AsSpan(off, nameLen)); off += nameLen;
                ushort symType = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;

                foundNames.Add(name);
                lastInstanceId = instId;
            }

            if (status == 0) break; // All done
            startInstance = lastInstanceId + 1;
        }

        // Verify all 4 tags from setup are present
        Assert.Contains("rate", foundNames);
        Assert.Contains("speed", foundNames);
        Assert.Contains("bigdata", foundNames);
        Assert.Contains("machine1", foundNames);
        Assert.Equal(4, foundNames.Count);
    }

    // --- Helpers ---

    private static byte[] BuildSymbolicPath(string name)
    {
        int padded = name.Length % 2 != 0 ? name.Length + 1 : name.Length;
        var path = new byte[2 + padded];
        path[0] = 0x91;
        path[1] = (byte)name.Length;
        Encoding.ASCII.GetBytes(name, path.AsSpan(2));
        return path;
    }

    private static byte[] BuildMrRequest(byte serviceCode, byte[] pathBytes, byte[] data)
    {
        var mr = new byte[2 + pathBytes.Length + data.Length];
        mr[0] = serviceCode;
        mr[1] = (byte)(pathBytes.Length / 2);
        pathBytes.CopyTo(mr.AsSpan(2));
        data.CopyTo(mr.AsSpan(2 + pathBytes.Length));
        return mr;
    }

    private async Task<(byte generalStatus, byte[] data)> SendCipServiceAsync(
        NetworkStream stream, uint session, byte serviceCode, byte[] pathBytes, byte[] serviceData)
    {
        int pathSizeWords = pathBytes.Length / 2;
        var mrRequest = new byte[2 + pathBytes.Length + serviceData.Length];
        mrRequest[0] = serviceCode;
        mrRequest[1] = (byte)pathSizeWords;
        pathBytes.CopyTo(mrRequest.AsSpan(2));
        serviceData.CopyTo(mrRequest.AsSpan(2 + pathBytes.Length));

        var cpfBuf = new byte[2048];
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
