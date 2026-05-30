using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EthernetIPSharp.Cip;

// CIP Message Sniffer — logs ALL encapsulation commands with full detail,
// responds OK to everything. Used to see what the PLC sends.

const int TcpPort = 44818;
const int UdpPort = 2222;

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Track sessions and connections
uint nextSession = 1;
uint nextConnId = 0x10000;
var connections = new Dictionary<uint, ConnInfo>(); // OtoT connId -> info
var lastSeqNum = new Dictionary<uint, ushort>(); // OtoT connId -> last seen seq

// Start UDP listener
var udpTask = Task.Run(() => UdpListenerAsync(cts.Token));

// Start TCP listener
var tcpListener = new TcpListener(IPAddress.Any, TcpPort);
tcpListener.Start();
Log($"Listening on TCP {TcpPort} + UDP {UdpPort}");

try
{
    while (!cts.IsCancellationRequested)
    {
        var client = await tcpListener.AcceptTcpClientAsync(cts.Token);
        var ep = (IPEndPoint)client.Client.RemoteEndPoint!;
        Log($"TCP connection from {ep}");
        _ = Task.Run(() => HandleClientAsync(client, cts.Token));
    }
}
catch (OperationCanceledException) { }
finally { tcpListener.Stop(); }

return;

// ──────────────────────────────────────────────

async Task HandleClientAsync(TcpClient client, CancellationToken ct)
{
    using (client)
    {
        var stream = client.GetStream();
        var headerBuf = new byte[24];
        uint session = 0;
        var localEp = (IPEndPoint)client.Client.LocalEndPoint!;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await ReadExactAsync(stream, headerBuf, ct);
                if (read == 0) break;

                var hdr = EncapsulationHeader.Parse(headerBuf);
                byte[] payload = [];
                if (hdr.Length > 0)
                {
                    payload = new byte[hdr.Length];
                    if (await ReadExactAsync(stream, payload, ct) == 0) break;
                }

                Log($"═══ {hdr.Command} (0x{(ushort)hdr.Command:X4}) Session=0x{hdr.SessionHandle:X8} Len={hdr.Length} ═══");

                byte[]? response = hdr.Command switch
                {
                    EncapsulationCommand.RegisterSession => HandleRegisterSession(hdr, ref session),
                    EncapsulationCommand.UnregisterSession => HandleUnregisterSession(hdr, ref session),
                    EncapsulationCommand.SendRRData => HandleSendRRData(hdr, payload, session, localEp),
                    EncapsulationCommand.SendUnitData => HandleSendUnitData(hdr, payload, session),
                    EncapsulationCommand.ListIdentity => HandleListIdentity(hdr, localEp),
                    EncapsulationCommand.ListServices => HandleListServices(hdr),
                    _ => BuildReply(hdr, [], session),
                };

                if (response != null)
                {
                    Log($"  ← REPLY ({response.Length}B): {Hex(response)}");
                    await stream.WriteAsync(response, ct);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }

        Log("TCP connection closed");
    }
}

async Task UdpListenerAsync(CancellationToken ct)
{
    using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, UdpPort));
    Log($"UDP listening on {UdpPort}");

    try
    {
        while (!ct.IsCancellationRequested)
        {
            var result = await udp.ReceiveAsync(ct);
            var data = result.Buffer;
            var from = result.RemoteEndPoint;

            if (data.Length < 6) { Log($"  [UDP] Short packet ({data.Length}B) from {from}"); continue; }

            ushort itemCount = BinaryPrimitives.ReadUInt16LittleEndian(data);
            int off = 2;

            Log($"  [UDP] {data.Length}B from {from}, {itemCount} CPF items");

            for (int i = 0; i < itemCount && off + 4 <= data.Length; i++)
            {
                ushort typeId = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off));
                ushort len = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off + 2));
                off += 4;
                if (off + len > data.Length) break;

                var itemData = data.AsSpan(off, len);

                switch (typeId)
                {
                    case 0x8002: // SequencedAddress
                        if (len >= 8)
                        {
                            uint connId = BinaryPrimitives.ReadUInt32LittleEndian(itemData);
                            uint seqNum = BinaryPrimitives.ReadUInt32LittleEndian(itemData.Slice(4));
                            string connName = connections.TryGetValue(connId, out var ci) ? ci.Name : "???";
                            Log($"    Item[{i}] SeqAddr: ConnId=0x{connId:X8} ({connName}) Seq={seqNum}");
                        }
                        break;
                    case 0x00B1: // ConnectedData
                        Log($"    Item[{i}] ConnData ({len}B): {Hex(itemData)}");
                        break;
                    default:
                        Log($"    Item[{i}] Type=0x{typeId:X4} ({len}B): {Hex(itemData)}");
                        break;
                }

                off += len;
            }
        }
    }
    catch (OperationCanceledException) { }
}

// ──── Encapsulation handlers ────

byte[] HandleRegisterSession(EncapsulationHeader hdr, ref uint session)
{
    session = nextSession++;
    Log($"  → RegisterSession → handle=0x{session:X8}");
    var payload = new byte[4];
    BinaryPrimitives.WriteUInt16LittleEndian(payload, 1); // protocol version
    return BuildReply(hdr, payload, session);
}

byte[] HandleUnregisterSession(EncapsulationHeader hdr, ref uint session)
{
    Log($"  → UnregisterSession handle=0x{session:X8}");
    session = 0;
    return BuildReply(hdr, [], 0);
}

byte[] HandleListIdentity(EncapsulationHeader hdr, IPEndPoint localEp)
{
    Log("  → ListIdentity");
    // Minimal identity response
    var identity = new byte[64];
    int o = 0;
    BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(o), 1); o += 2; // item count
    BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(o), 0x000C); o += 2; // CipIdentity
    int lenOff = o; o += 2; // length placeholder
    BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(o), 1); o += 2; // version
    // sockaddr (16 bytes)
    BinaryPrimitives.WriteInt16BigEndian(identity.AsSpan(o), 2); o += 2; // AF_INET
    BinaryPrimitives.WriteUInt16BigEndian(identity.AsSpan(o), (ushort)TcpPort); o += 2;
    localEp.Address.GetAddressBytes().CopyTo(identity.AsSpan(o)); o += 4;
    o += 8; // zero pad
    BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(o), 12); o += 2; // vendor
    BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(o), 14); o += 2; // device type (safety)
    BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(o), 1); o += 2; // product code
    identity[o++] = 1; identity[o++] = 0; // revision
    BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(o), 0x0070); o += 2; // status
    BinaryPrimitives.WriteUInt32LittleEndian(identity.AsSpan(o), 0xC0FFEE42); o += 4; // serial
    identity[o++] = 8; // name length
    "TestSafe"u8.CopyTo(identity.AsSpan(o)); o += 8;
    identity[o++] = 0; // state
    BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(lenOff), (ushort)(o - lenOff - 2));
    return BuildReply(hdr, identity.AsSpan(0, o).ToArray(), 0);
}

byte[] HandleListServices(EncapsulationHeader hdr)
{
    Log("  → ListServices");
    var payload = new byte[26];
    BinaryPrimitives.WriteUInt16LittleEndian(payload, 1); // count
    BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(2), 0x0100); // type
    BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(4), 20); // length
    BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(6), 1); // version
    BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(8), 0x0120); // capability flags
    "Communications\0\0"u8.CopyTo(payload.AsSpan(10));
    return BuildReply(hdr, payload, 0);
}

byte[] HandleSendRRData(EncapsulationHeader hdr, byte[] payload, uint session, IPEndPoint localEp)
{
    if (payload.Length < 6)
    {
        Log("  → SendRRData: payload too short");
        return BuildReply(hdr, [], session);
    }

    var cpfData = payload.AsSpan(6);
    var items = CpfParser.Parse(cpfData);

    Log($"  → SendRRData: {items.Length} CPF items");
    for (int i = 0; i < items.Length; i++)
        Log($"    Item[{i}] Type=0x{(ushort)items[i].TypeId:X4} ({items[i].TypeId}) Len={items[i].Data.Length}");

    // Find the unconnected data item
    CpfItem? dataItem = null;
    foreach (var item in items)
        if (item.TypeId == CpfItemType.UnconnectedData) { dataItem = item; break; }

    if (dataItem == null)
    {
        Log("  → No UnconnectedData item found");
        return BuildReply(hdr, [], session);
    }

    // Parse MR request
    if (!MrCodec.TryParseRequest(dataItem.Value.Data, out var svc, out var path, out var data))
    {
        Log("  → Failed to parse MR request");
        return BuildReply(hdr, [], session);
    }

    Log($"  → Service=0x{svc:X2} ({ServiceName(svc)}) Path=[{path}]");
    if (data.Length > 0)
        Log($"    Data ({data.Length}B): {Hex(data.Span)}");

    // Handle Forward Open specially
    if (svc == 0x54 || svc == 0x5B)
        return HandleForwardOpen(hdr, svc, path, data, session, localEp);

    // Handle Forward Close
    if (svc == 0x4E)
        return HandleForwardClose(hdr, data, session);

    // Handle Unconnected Send (0x52) — unwrap inner message
    if (svc == 0x52)
        return HandleUnconnectedSend(hdr, data, session, localEp);

    // Generic success response
    var mrReply = BuildMrReply(svc, 0x00, []);
    return BuildSendRRDataReply(hdr, mrReply, session);
}

byte[] HandleSendUnitData(EncapsulationHeader hdr, byte[] payload, uint session)
{
    if (payload.Length < 6)
    {
        Log("  → SendUnitData: payload too short");
        return BuildReply(hdr, [], session);
    }

    var cpfData = payload.AsSpan(6);
    var items = CpfParser.Parse(cpfData);

    Log($"  → SendUnitData (Class 3 Connected): {items.Length} CPF items");

    uint connId = 0;

    foreach (var item in items)
    {
        switch (item.TypeId)
        {
            case CpfItemType.ConnectedAddress:
                if (item.Data.Length >= 4)
                {
                    connId = BinaryPrimitives.ReadUInt32LittleEndian(item.Data.Span);
                    string connName = connections.TryGetValue(connId, out var ci) ? ci.Name : "???";
                    Log($"    ConnectedAddr: ConnId=0x{connId:X8} ({connName})");
                }
                break;
            case CpfItemType.ConnectedData:
                Log($"    ConnectedData ({item.Data.Length}B): {Hex(item.Data.Span)}");

                // Class 3: first 2 bytes are CIP sequence count, then MR request
                if (item.Data.Length >= 4)
                {
                    ushort cipSeq = BinaryPrimitives.ReadUInt16LittleEndian(item.Data.Span);
                    Log($"    CIP SeqCount={cipSeq}");

                    // Discard duplicate (keepalive) — same seq as last time
                    if (lastSeqNum.TryGetValue(connId, out var prev) && prev == cipSeq)
                    {
                        Log($"    (duplicate seq, keepalive — discarded)");
                        // Still reply so the connection stays alive
                        var dupReply = BuildMrReply(item.Data.Span[2], 0x00, []);
                        var dupData = new byte[2 + dupReply.Length];
                        BinaryPrimitives.WriteUInt16LittleEndian(dupData, cipSeq);
                        dupReply.CopyTo(dupData.AsSpan(2));
                        uint dupConnId = connections.TryGetValue(connId, out var ci3) ? ci3.ToConnId : connId;
                        return BuildSendUnitDataReply(hdr, dupConnId, dupData, session);
                    }
                    lastSeqNum[connId] = cipSeq;

                    var mrData = item.Data.Slice(2);
                    if (MrCodec.TryParseRequest(mrData, out var svc, out var path, out var data))
                    {
                        Log($"    Service=0x{svc:X2} ({ServiceName(svc)}) Path=[{path}]");
                        if (data.Length > 0)
                            Log($"    Data ({data.Length}B): {Hex(data.Span)}");
                    }
                    else
                    {
                        Log($"    MR parse failed, raw: {Hex(mrData.Span)}");
                    }

                    // Build Class 3 reply: sequence count + MR reply
                    var mrReply = BuildMrReply(item.Data.Span[2], 0x00, []);
                    var connReplyData = new byte[2 + mrReply.Length];
                    BinaryPrimitives.WriteUInt16LittleEndian(connReplyData, cipSeq);
                    mrReply.CopyTo(connReplyData.AsSpan(2));

                    // Reply using originator's TO connection ID, not our OT ID
                    uint replyConnId = connections.TryGetValue(connId, out var ci2) ? ci2.ToConnId : connId;
                    return BuildSendUnitDataReply(hdr, replyConnId, connReplyData, session);
                }
                break;
            default:
                Log($"    Item Type=0x{(ushort)item.TypeId:X4} ({item.Data.Length}B): {Hex(item.Data.Span)}");
                break;
        }
    }

    return BuildReply(hdr, [], session);
}

byte[] HandleForwardOpen(EncapsulationHeader hdr, byte svc, CipPath path, ReadOnlyMemory<byte> data, uint session, IPEndPoint localEp)
{
    var d = data.Span;
    if (d.Length < 36)
    {
        Log($"    FwdOpen data too short ({d.Length}B)");
        return BuildSendRRDataReply(hdr, BuildMrReply(svc, 0x01, []), session);
    }

    byte timeTick = d[0];
    byte timeoutTicks = d[1];
    uint otConnId = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(2));
    uint toConnId = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(6));
    ushort connSerial = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(10));
    ushort origVendor = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(12));
    uint origSerial = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(14));
    byte timeoutMult = d[18];
    uint otRpi = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(22));
    ushort otParams = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(26));
    uint toRpi = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(28));
    ushort toParams = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(32));
    byte transportTrigger = d[34];
    byte connPathSize = d[35];

    int otSize = otParams & 0x01FF;
    int toSize = toParams & 0x01FF;
    bool otP2P = (otParams & 0x4000) != 0;
    bool toP2P = (toParams & 0x4000) != 0;
    bool otFixed = (otParams & 0x0200) == 0;
    bool toFixed = (toParams & 0x0200) == 0;
    int otPriority = (otParams >> 10) & 0x03;
    int toPriority = (toParams >> 10) & 0x03;
    byte transportClass = (byte)(transportTrigger & 0x0F);
    bool server = (transportTrigger & 0x80) != 0;

    Log($"    ┌─ Forward Open ─────────────────────────────────────");
    Log($"    │ TimeTick={timeTick} TimeoutTicks={timeoutTicks}");
    Log($"    │ OT ConnId=0x{otConnId:X8}  TO ConnId=0x{toConnId:X8}");
    Log($"    │ ConnSerial={connSerial} OrigVendor=0x{origVendor:X4} OrigSerial=0x{origSerial:X8}");
    Log($"    │ TimeoutMult={timeoutMult} (x{4 << timeoutMult})");
    Log($"    │ OT: RPI={otRpi}us Size={otSize} P2P={otP2P} Fixed={otFixed} Pri={otPriority}");
    Log($"    │ TO: RPI={toRpi}us Size={toSize} P2P={toP2P} Fixed={toFixed} Pri={toPriority}");
    Log($"    │ Transport: Class{transportClass} {(server ? "Server" : "Client")} Trigger=0x{transportTrigger:X2}");
    Log($"    │ ConnPathSize={connPathSize} words");

    // Parse connection path
    if (d.Length > 36)
    {
        var connPathBytes = d.Slice(36);
        Log($"    │ ConnPath ({connPathBytes.Length}B): {Hex(connPathBytes)}");

        // Try to parse the application path
        var (appPath, consumed) = CipPath.Parse(connPathBytes);
        Log($"    │ AppPath: [{appPath}] (consumed {consumed}B)");

        // Check for safety network segment (0x50 header)
        if (consumed < connPathBytes.Length)
        {
            var remaining = connPathBytes.Slice(consumed);
            Log($"    │ Remaining ({remaining.Length}B): {Hex(remaining)}");
            if (remaining.Length > 0 && remaining[0] == 0x50)
                Log($"    │ *** Safety Network Segment detected ***");
        }
    }
    Log($"    └──────────────────────────────────────────────────");

    // Allocate our connection ID for O→T
    uint ourOtConnId = nextConnId++;
    string connName = $"Serial={connSerial} Class{transportClass} {(server ? "Srv" : "Cli")}";
    connections[ourOtConnId] = new ConnInfo(connName, connSerial, transportClass, server, toConnId);

    Log($"    Assigned OT ConnId=0x{ourOtConnId:X8} for '{connName}'");

    // Build Forward Open reply
    var reply = new byte[26];
    int ro = 0;
    BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(ro), ourOtConnId); ro += 4; // OT conn ID (we chose)
    BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(ro), toConnId); ro += 4; // TO conn ID (echo back)
    BinaryPrimitives.WriteUInt16LittleEndian(reply.AsSpan(ro), connSerial); ro += 2;
    BinaryPrimitives.WriteUInt16LittleEndian(reply.AsSpan(ro), origVendor); ro += 2;
    BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(ro), origSerial); ro += 4;
    BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(ro), otRpi); ro += 4; // OT API
    BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(ro), toRpi); ro += 4; // TO API
    reply[ro++] = 0; // app reply size (words)
    reply[ro++] = 0; // reserved

    var mrReply = BuildMrReply(svc, 0x00, reply.AsSpan(0, ro));

    // Class 3: no sockaddr items (TCP-based, uses SendUnitData on same session)
    // Class 0/1: include sockaddr items for UDP
    if (transportClass == 3)
    {
        return BuildSendRRDataReply(hdr, mrReply, session);
    }
    else
    {
        var sockaddr = BuildSockaddrInfo(localEp.Address, UdpPort);
        var replyItems = new CpfItem[4];
        replyItems[0] = new CpfItem { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty };
        replyItems[1] = new CpfItem { TypeId = CpfItemType.UnconnectedData, Data = mrReply };
        replyItems[2] = new CpfItem { TypeId = CpfItemType.SockaddrInfoOtoT, Data = sockaddr };
        replyItems[3] = new CpfItem { TypeId = CpfItemType.SockaddrInfoTtoO, Data = sockaddr };

        var cpfBuf = new byte[4096];
        int cpfLen = CpfParser.Write(cpfBuf, replyItems);

        var responsePayload = new byte[6 + cpfLen];
        cpfBuf.AsSpan(0, cpfLen).CopyTo(responsePayload.AsSpan(6));

        return BuildReply(hdr, responsePayload, session);
    }
}

byte[] HandleForwardClose(EncapsulationHeader hdr, ReadOnlyMemory<byte> data, uint session)
{
    var d = data.Span;
    if (d.Length >= 10)
    {
        ushort connSerial = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(2));
        ushort origVendor = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(4));
        uint origSerial = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(6));
        Log($"    Forward Close: Serial={connSerial} OrigVendor=0x{origVendor:X4} OrigSerial=0x{origSerial:X8}");
    }
    else
    {
        Log($"    Forward Close: data ({d.Length}B): {Hex(d)}");
    }

    // Success reply
    var reply = new byte[10];
    if (d.Length >= 10) d.Slice(2, 8).CopyTo(reply.AsSpan(2)); // echo triad
    var mrReply = BuildMrReply(0x4E, 0x00, reply);
    return BuildSendRRDataReply(hdr, mrReply, session);
}

byte[] HandleUnconnectedSend(EncapsulationHeader hdr, ReadOnlyMemory<byte> data, uint session, IPEndPoint localEp)
{
    var d = data.Span;
    if (d.Length < 6)
    {
        Log($"    Unconnected Send: data too short ({d.Length}B)");
        return BuildSendRRDataReply(hdr, BuildMrReply(0x52, 0x01, []), session);
    }

    byte timeTick = d[0];
    byte timeoutTicks = d[1];
    ushort msgLen = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(2));

    Log($"    Unconnected Send: TimeTick={timeTick} TimeoutTicks={timeoutTicks} MsgLen={msgLen}");

    if (d.Length >= 4 + msgLen && msgLen >= 2)
    {
        var innerMsg = d.Slice(4, msgLen);
        Log($"    Inner message ({msgLen}B): {Hex(innerMsg)}");

        // Parse inner MR request
        if (MrCodec.TryParseRequest(innerMsg.ToArray(), out var innerSvc, out var innerPath, out var innerData))
        {
            Log($"    Inner Service=0x{innerSvc:X2} ({ServiceName(innerSvc)}) Path=[{innerPath}]");
            if (innerData.Length > 0)
                Log($"    Inner Data ({innerData.Length}B): {Hex(innerData.Span)}");

            // Route path after inner message
            int routeOff = 4 + msgLen;
            if (msgLen % 2 != 0) routeOff++; // pad
            if (routeOff < d.Length)
            {
                var routeBytes = d.Slice(routeOff);
                Log($"    Route path ({routeBytes.Length}B): {Hex(routeBytes)}");
            }

            // If it's a Forward Open inside unconnected send, handle it
            if (innerSvc == 0x54 || innerSvc == 0x5B)
                return HandleForwardOpen(hdr, innerSvc, innerPath, innerData, session, localEp);

            if (innerSvc == 0x4E)
                return HandleForwardClose(hdr, innerData, session);

            // Generic success for the inner service
            var innerReply = BuildMrReply(innerSvc, 0x00, []);
            return BuildSendRRDataReply(hdr, innerReply, session);
        }
    }

    return BuildSendRRDataReply(hdr, BuildMrReply(0x52, 0x00, []), session);
}

// ──── Helpers ────

byte[] BuildMrReply(byte serviceCode, byte generalStatus, ReadOnlySpan<byte> data)
{
    var reply = new byte[4 + data.Length];
    reply[0] = (byte)(serviceCode | 0x80); // reply bit
    reply[1] = 0; // reserved
    reply[2] = generalStatus;
    reply[3] = 0; // additional status size
    data.CopyTo(reply.AsSpan(4));
    return reply;
}

byte[] BuildSendRRDataReply(EncapsulationHeader hdr, byte[] mrReply, uint session)
{
    var replyItems = new CpfItem[2];
    replyItems[0] = new CpfItem { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty };
    replyItems[1] = new CpfItem { TypeId = CpfItemType.UnconnectedData, Data = mrReply };

    var cpfBuf = new byte[4096];
    int cpfLen = CpfParser.Write(cpfBuf, replyItems);

    var responsePayload = new byte[6 + cpfLen];
    cpfBuf.AsSpan(0, cpfLen).CopyTo(responsePayload.AsSpan(6));

    return BuildReply(hdr, responsePayload, session);
}

byte[] BuildSendUnitDataReply(EncapsulationHeader hdr, uint connId, byte[] connData, uint session)
{
    var replyItems = new CpfItem[2];
    var connIdBytes = new byte[4];
    BinaryPrimitives.WriteUInt32LittleEndian(connIdBytes, connId);
    replyItems[0] = new CpfItem { TypeId = CpfItemType.ConnectedAddress, Data = connIdBytes };
    replyItems[1] = new CpfItem { TypeId = CpfItemType.ConnectedData, Data = connData };

    var cpfBuf = new byte[4096];
    int cpfLen = CpfParser.Write(cpfBuf, replyItems);

    var responsePayload = new byte[6 + cpfLen];
    cpfBuf.AsSpan(0, cpfLen).CopyTo(responsePayload.AsSpan(6));

    return BuildReply(hdr, responsePayload, session);
}

byte[] BuildReply(EncapsulationHeader hdr, byte[] payload, uint session)
{
    var response = new byte[24 + payload.Length];
    var replyHdr = new EncapsulationHeader
    {
        Command = hdr.Command,
        Length = (ushort)payload.Length,
        SessionHandle = session,
        Status = EncapsulationStatus.Success,
        SenderContext = hdr.SenderContext,
    };
    replyHdr.WriteTo(response);
    payload.CopyTo(response.AsSpan(24));
    return response;
}

byte[] BuildSockaddrInfo(IPAddress addr, int port)
{
    var buf = new byte[16];
    BinaryPrimitives.WriteInt16BigEndian(buf, 2); // AF_INET
    BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), (ushort)port);
    addr.GetAddressBytes().CopyTo(buf.AsSpan(4));
    return buf;
}

async Task<int> ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
{
    int total = 0;
    while (total < buffer.Length)
    {
        int n = await stream.ReadAsync(buffer.AsMemory(total), ct);
        if (n == 0) return 0;
        total += n;
    }
    return total;
}

string ServiceName(byte svc) => svc switch
{
    0x01 => "Get_Attribute_All",
    0x02 => "Set_Attribute_All",
    0x03 => "Get_Attribute_List",
    0x04 => "Set_Attribute_List",
    0x05 => "Reset",
    0x0E => "Get_Attribute_Single",
    0x10 => "Set_Attribute_Single",
    0x4B => "Execute_PCCC",
    0x4C => "Read_Tag",
    0x4D => "Write_Tag",
    0x4E => "Forward_Close",
    0x52 => "Unconnected_Send",
    0x54 => "Forward_Open",
    0x56 => "Propose_TUNID",
    0x57 => "Apply_TUNID",
    0x5B => "Large_Forward_Open",
    _ => $"Unknown(0x{svc:X2})",
};

string Hex(ReadOnlySpan<byte> data)
{
    if (data.Length == 0) return "(empty)";
    var parts = new string[Math.Min(data.Length, 64)];
    for (int i = 0; i < parts.Length; i++)
        parts[i] = data[i].ToString("X2");
    string s = string.Join(" ", parts);
    if (data.Length > 64) s += $" ... ({data.Length}B total)";
    return s;
}

void Log(string msg) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {msg}");

record ConnInfo(string Name, ushort Serial, byte TransportClass, bool Server, uint ToConnId);
