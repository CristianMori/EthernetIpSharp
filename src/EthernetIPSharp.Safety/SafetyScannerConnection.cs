using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Protocol;
using EthernetIPSharp.Protocol.Messages;

namespace EthernetIPSharp.Safety;

/// <summary>
/// Parsed safety application reply from a Forward Open response.
/// </summary>
public readonly struct SafetyAppReply
{
    public ushort ConsumerNumber { get; init; }
    public ushort TargetVendorId { get; init; }
    public uint TargetDeviceSerial { get; init; }
    public ushort TargetConnectionSerial { get; init; } // SV Instance ID
    public ushort InitialTimestamp { get; init; }
    public ushort InitialRolloverValue { get; init; }

    public static SafetyAppReply Parse(ReadOnlySpan<byte> data)
    {
        var result = new SafetyAppReply
        {
            ConsumerNumber = BinaryPrimitives.ReadUInt16LittleEndian(data),
            TargetVendorId = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2)),
            TargetDeviceSerial = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4)),
            TargetConnectionSerial = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(8)),
        };
        if (data.Length >= 14)
        {
            return result with
            {
                InitialTimestamp = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(10)),
                InitialRolloverValue = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(12)),
            };
        }
        return result;
    }
}

/// <summary>
/// CIP Safety scanner (originator) connection.
/// Manages a pair of Forward Opens (server + client) for safety I/O exchange.
/// </summary>
public sealed class SafetyScannerConnection : IAsyncDisposable
{
    private readonly EipScanner _scanner;
    private readonly IEipUdpTransport _udp;
    private readonly SafetyFormat _format;

    // Server connection: we produce O→T, target sends TCOO back
    private uint _serverOtoTId;   // target assigned
    private uint _serverTtoOId;   // we assigned
    private ushort _serverConnSerial;
    private IPEndPoint? _serverTargetEndpoint;

    // Client connection: target produces T→O, we send TCOO
    private uint _clientOtoTId;   // target assigned
    private uint _clientTtoOId;   // we assigned
    private ushort _clientConnSerial;

    // Originator identity
    private ushort _origVendor;
    private uint _origSerial;

    // Route for Forward Close
    private byte[] _routePrefix = Array.Empty<byte>();

    // Target identity (from app reply)
    private SafetyAppReply _targetAppReply;

    // PID seeds — for data WE produce on server connection
    private byte _pidSeedS1;
    private ushort _pidSeedS3;
    private uint _pidSeedS5;

    // Target PID seeds — for decoding data THEY produce on client connection
    private byte _tgtPidSeedS1;
    private ushort _tgtPidSeedS3;
    private uint _tgtPidSeedS5;

    // CID seeds — for TCOO we send on client connection
    private uint _cidSeedS5;

    // Target CID seeds — for decoding TCOO they send on server connection
    // (not needed — we just set consumerActive when we receive anything on server T→O)

    // Mode byte state
    private bool _runIdle;
    private byte _pingCount;
    private bool _consumerActive;
    private ushort _timestamp;
    // Our producer's rollover (used by Encode on server O->T). Seeded from
    // serverConfig.InitialRolloverValue at Open, incremented in ProduceServerData
    // every time _timestamp wraps 0xFFFF -> 0x0000. Extended-format CRC-S5
    // folds this into the seed, so any spec-compliant consumer would drift
    // out of sync after the first ~8.4 s if this counter stayed at 0.
    private ushort _rolloverCount;
    // Target's producer rollover (used by Decode on client T<-O). Advanced
    // here on every observed wire-timestamp wrap. Must be kept distinct from
    // _rolloverCount — they wrap on independent schedules.
    private ushort _tgtRolloverCount;
    private ushort _tgtLastTs;
    private bool _tgtRolloverInitialized;
    private byte _lastTargetPing = 0xFF;

    // Production
    private Thread? _productionThread;
    private CancellationTokenSource? _productionCts;
    private uint _serverEncapSeq = 1;
    private uint _clientEncapSeq = 1;
    private byte[] _outputData = Array.Empty<byte>();
    private int _inputDataSize;

    /// <summary>Fired when safety input data is received from the target.</summary>
    public event Action<ReadOnlyMemory<byte>>? DataReceived;

    /// <summary>Fired with log messages for debugging.</summary>
    public event Action<string>? Log;

    /// <summary>True if the connection is open and active.</summary>
    public bool IsOpen { get; private set; }

    private SafetyScannerConnection(EipScanner scanner, IEipUdpTransport udp, SafetyFormat format)
    {
        _scanner = scanner;
        _udp = udp;
        _format = format;
    }

    /// <summary>
    /// Open a safety connection pair to a target device.
    /// </summary>
    /// <param name="scanner">EIP scanner for TCP communication.</param>
    /// <param name="udp">UDP transport for I/O data.</param>
    /// <param name="serverConfig">Config for server connection (we produce O→T).</param>
    /// <param name="clientConfig">Config for client connection (target produces T→O).</param>
    /// <param name="origVendor">Originator vendor ID.</param>
    /// <param name="origSerial">Originator device serial number.</param>
    /// <param name="routePrefix">Port segment for routing (e.g., backplane slot). Empty for direct.</param>
    /// <param name="serverAppPath">Electronic key + assembly path for server connection.</param>
    /// <param name="clientAppPath">Electronic key + assembly path for client connection.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<SafetyScannerConnection> OpenAsync(
        EipScanner scanner,
        IEipUdpTransport udp,
        SafetyForwardOpenConfig serverConfig,
        SafetyForwardOpenConfig clientConfig,
        ushort origVendor, uint origSerial,
        byte[]? routePrefix = null,
        byte[]? serverAppPath = null,
        byte[]? clientAppPath = null,
        CancellationToken ct = default)
    {
        var conn = new SafetyScannerConnection(scanner, udp, serverConfig.Format);
        conn._origVendor = origVendor;
        conn._origSerial = origSerial;
        conn._outputData = new byte[serverConfig.ConsumedDataSize];
        conn._inputDataSize = clientConfig.ProducedDataSize;
        conn._routePrefix = routePrefix ?? Array.Empty<byte>();
        // Seed producer state from the values we advertise in the safety
        // segment — a spec-compliant consumer reads the same values off the
        // segment and starts its rollover counter there, so both ends must
        // agree from frame 1.
        conn._timestamp = serverConfig.InitialTimestamp;
        conn._rolloverCount = serverConfig.InitialRolloverValue;

        // Generate unique connection serials
        conn._serverConnSerial = (ushort)(Environment.TickCount & 0xFFFF);
        conn._clientConnSerial = (ushort)((Environment.TickCount + 1) & 0xFFFF);

        var route = conn._routePrefix;

        // Open server Forward Open (we produce O→T)
        conn.LogMsg("Opening server connection (we produce)...");
        var (serverSvcData, serverCmPath) = serverAppPath != null
            ? SafetyForwardOpenBuilder.Build(
                serverConfig, conn._serverConnSerial, origVendor, origSerial, 0xA0, route, serverAppPath)
            : SafetyForwardOpenBuilder.Build(
                serverConfig, conn._serverConnSerial, origVendor, origSerial, 0xA0);

        conn.LogMsg($"Server FwdOpen data ({serverSvcData.Length}B): {string.Join(" ", serverSvcData.Select(b => b.ToString("X2")))}");

        var (serverResp, serverCpf) = await scanner.SendExplicitRawAsync(
            0x54, serverCmPath, serverSvcData, ct);

        if (!serverResp.Status.IsSuccess)
        {
            ushort extStatus = serverResp.Status.AdditionalStatus?.Length > 0
                ? serverResp.Status.AdditionalStatus[0] : (ushort)0;
            var respData = serverResp.Data.ToArray();
            conn.LogMsg($"Server FwdOpen response ({respData.Length}B): {string.Join(" ", respData.Select(b => b.ToString("X2")))}");
            throw new InvalidOperationException(
                $"Server Forward Open failed: GS=0x{serverResp.Status.GeneralStatus:X2} ES=0x{extStatus:X4}");
        }

        // Parse server response
        var srd = serverResp.Data.ToArray();
        conn._serverOtoTId = BinaryPrimitives.ReadUInt32LittleEndian(srd);
        conn._serverTtoOId = BinaryPrimitives.ReadUInt32LittleEndian(srd.AsSpan(4));
        byte appReplySize = srd[24];
        if (appReplySize > 0 && srd.Length >= 26 + appReplySize * 2)
        {
            conn._targetAppReply = SafetyAppReply.Parse(srd.AsSpan(26));
            conn.LogMsg($"  Target: Vendor=0x{conn._targetAppReply.TargetVendorId:X4} " +
                $"Serial=0x{conn._targetAppReply.TargetDeviceSerial:X8} " +
                $"SVInst={conn._targetAppReply.TargetConnectionSerial}");
        }

        // Extract target UDP endpoint from sockaddr
        foreach (var item in serverCpf)
        {
            if (item.TypeId == CpfItemType.SockaddrInfoOtoT && item.Data.Length >= 8)
            {
                var port = BinaryPrimitives.ReadUInt16BigEndian(item.Data.Span.Slice(2));
                var addr = new IPAddress(item.Data.Slice(4, 4).ToArray());
                if (addr.Equals(IPAddress.Any))
                    addr = scanner.RemoteEndpoint!.Address;
                conn._serverTargetEndpoint = new IPEndPoint(addr, port);
                conn.LogMsg($"  Target UDP: {conn._serverTargetEndpoint}");
            }
        }

        // Ensure IPv4 — our UDP socket is IPv4
        if (conn._serverTargetEndpoint != null && conn._serverTargetEndpoint.Address.IsIPv4MappedToIPv6)
            conn._serverTargetEndpoint = new IPEndPoint(conn._serverTargetEndpoint.Address.MapToIPv4(), conn._serverTargetEndpoint.Port);
        if (conn._serverTargetEndpoint == null)
        {
            var targetAddr = scanner.RemoteEndpoint!.Address;
            if (targetAddr.IsIPv4MappedToIPv6) targetAddr = targetAddr.MapToIPv4();
            conn._serverTargetEndpoint = new IPEndPoint(targetAddr, EipUdpTransport.IoPort);
        }

        conn.LogMsg($"  Server OT=0x{conn._serverOtoTId:X8} TO=0x{conn._serverTtoOId:X8}");

        // Open client Forward Open (target produces T→O)
        conn.LogMsg("Opening client connection (target produces)...");
        var (clientSvcData, clientCmPath) = clientAppPath != null
            ? SafetyForwardOpenBuilder.Build(
                clientConfig, conn._clientConnSerial, origVendor, origSerial, 0x20, route, clientAppPath)
            : SafetyForwardOpenBuilder.Build(
                clientConfig, conn._clientConnSerial, origVendor, origSerial, 0x20);

        var (clientResp, clientCpf) = await scanner.SendExplicitRawAsync(
            0x54, clientCmPath, clientSvcData, ct);

        if (!clientResp.Status.IsSuccess)
        {
            ushort extStatus = clientResp.Status.AdditionalStatus?.Length > 0
                ? clientResp.Status.AdditionalStatus[0] : (ushort)0;
            throw new InvalidOperationException(
                $"Client Forward Open failed: GS=0x{clientResp.Status.GeneralStatus:X2} ES=0x{extStatus:X4}");
        }

        var crdArr = clientResp.Data.ToArray();
        conn._clientOtoTId = BinaryPrimitives.ReadUInt32LittleEndian(crdArr);
        conn._clientTtoOId = BinaryPrimitives.ReadUInt32LittleEndian(crdArr.AsSpan(4));

        // Parse client app reply — it has a different SVInst from server
        SafetyAppReply clientAppReply = default;
        byte clientAppReplySize = crdArr[24];
        if (clientAppReplySize > 0 && crdArr.Length >= 26 + clientAppReplySize * 2)
            clientAppReply = SafetyAppReply.Parse(crdArr.AsSpan(26));

        conn.LogMsg($"  Client OT=0x{conn._clientOtoTId:X8} TO=0x{conn._clientTtoOId:X8} SVInst={clientAppReply.TargetConnectionSerial}");

        // Server SVInst — for data WE produce on server O→T
        var serverSvInst = conn._targetAppReply.TargetConnectionSerial;
        // Client SVInst — for data TARGET produces on client T→O
        var clientSvInst = clientAppReply.TargetConnectionSerial;
        var tgtVendor = conn._targetAppReply.TargetVendorId;
        var tgtSerial = conn._targetAppReply.TargetDeviceSerial;

        // PID seed uses PRODUCER's identity + PRODUCER's connection serial.
        // Server O→T: WE are the producer → our identity + our connSerial
        conn._pidSeedS1 = SafetyCrc.PidCidSeedS1(origVendor, origSerial, conn._serverConnSerial);
        conn._pidSeedS3 = SafetyCrc.PidCidSeedS3(origVendor, origSerial, conn._serverConnSerial);
        conn._pidSeedS5 = SafetyCrc.PidCidSeedS5(origVendor, origSerial, conn._serverConnSerial);

        // Client T→O: TARGET is the producer → target identity + target's SVInst (TargetConnectionSerial)
        conn._tgtPidSeedS1 = SafetyCrc.PidCidSeedS1(tgtVendor, tgtSerial, clientSvInst);
        conn._tgtPidSeedS3 = SafetyCrc.PidCidSeedS3(tgtVendor, tgtSerial, clientSvInst);
        conn._tgtPidSeedS5 = SafetyCrc.PidCidSeedS5(tgtVendor, tgtSerial, clientSvInst);

        // CID seed for TCOO we send on client O→T: our identity + our client connSerial
        conn._cidSeedS5 = SafetyCrc.PidCidSeedS5(origVendor, origSerial, conn._clientConnSerial);

        // Log seeds to console directly (Log event may not be subscribed yet)
        Console.WriteLine($"[SAFETY] Target: Vendor=0x{clientAppReply.TargetVendorId:X4} Serial=0x{clientAppReply.TargetDeviceSerial:X8} ServerSV={serverSvInst} ClientSV={clientSvInst}");
        Console.WriteLine($"[SAFETY] Server OT=0x{conn._serverOtoTId:X8} TO=0x{conn._serverTtoOId:X8}");
        Console.WriteLine($"[SAFETY] Client OT=0x{conn._clientOtoTId:X8} TO=0x{conn._clientTtoOId:X8}");
        Console.WriteLine($"[SAFETY] PID S5=0x{conn._pidSeedS5:X6} TgtPID S5=0x{conn._tgtPidSeedS5:X6}");
        Console.WriteLine($"[SAFETY] Target UDP: {conn._serverTargetEndpoint}");

        // Subscribe to UDP — typed messages from the transport's CPF parser
        udp.MessageReceived += conn.OnUdpMessageReceived;

        // Start production thread for server connection using O→T RPI
        uint serverOtRpi = serverConfig.OtoTRpi != 0 ? serverConfig.OtoTRpi : serverConfig.Rpi;
        Console.WriteLine($"[SAFETY] Server production interval: {serverOtRpi / 1000.0}ms");
        conn._productionCts = new CancellationTokenSource();
        var prodCts = conn._productionCts;
        long rpiTicks = (long)serverOtRpi * Stopwatch.Frequency / 1_000_000;
        long sleepThreshold = 2 * Stopwatch.Frequency / 1000;
        conn._productionThread = new Thread(() =>
        {
            long nextSend = Stopwatch.GetTimestamp() + rpiTicks;
            while (!prodCts.Token.IsCancellationRequested)
            {
                long remaining = nextSend - Stopwatch.GetTimestamp();
                if (remaining > sleepThreshold)
                    Thread.Sleep(1);
                else if (remaining > 0)
                    while (Stopwatch.GetTimestamp() < nextSend && !prodCts.Token.IsCancellationRequested)
                        Thread.SpinWait(1);
                else
                {
                    conn.ProduceServerData();
                    nextSend += rpiTicks;
                }
            }
        })
        { IsBackground = true, Priority = ThreadPriority.AboveNormal, Name = "Safety-Scanner-Produce" };
        conn._productionThread.Start();

        conn.IsOpen = true;
        conn.LogMsg("Safety connection open. Producing cold start (run=0, ts=0)...");
        return conn;
    }

    /// <summary>Set the output data to send to the target.</summary>
    public void SetOutputData(ReadOnlySpan<byte> data)
    {
        data.CopyTo(_outputData);
    }

    /// <summary>Produce safety-framed data on the server O→T connection.</summary>
    private void ProduceServerData()
    {
        if (!IsOpen || _serverTargetEndpoint == null) return;

        try
        {
            bool runIdle = _consumerActive && _runIdle;
            // Snapshot both counters BEFORE advancing them. The frame we're
            // about to encode carries the OLD timestamp with the OLD rollover;
            // the consumer detects the wrap from the *next* frame's timestamp
            // jump and bumps its own rollover to match. Reading rollover after
            // the bump would emit (old_ts, new_rollover) on the wrap frame,
            // which CRCs with the wrong seed and shows up as one failed frame
            // per wrap boundary.
            ushort timestamp = _consumerActive ? _timestamp : (ushort)0;
            ushort rollover = _rolloverCount;
            var mode = ModeByte.Create(runIdle, _pingCount);

            if (_consumerActive)
            {
                ushort prevTs = _timestamp;
                _timestamp += (ushort)(50000 / 128); // approximate RPI in 128µs ticks
                if (_timestamp < prevTs)
                    _rolloverCount = (ushort)(_rolloverCount + 1);
            }

            var buf = new byte[_outputData.Length * 2 + 16];
            int len = SafetyFrameCodec.Encode(buf, _outputData, _format, mode, timestamp,
                _pidSeedS1, _pidSeedS3, _pidSeedS5, rollover);

            _udp.SendIoData(_serverTargetEndpoint, _serverOtoTId, _serverEncapSeq, buf.AsSpan(0, len));
            if (_serverEncapSeq <= 3)
                LogMsg($"TX server O→T #{_serverEncapSeq} connID=0x{_serverOtoTId:X8} len={len} run={runIdle} ts={timestamp} wire=[{string.Join(" ", buf.AsSpan(0, len).ToArray().Select(b => b.ToString("X2")))}]");
            _serverEncapSeq++;
        }
        catch (Exception ex)
        {
            LogMsg($"ProduceServerData error: {ex.Message}");
        }
    }

    /// <summary>Handle incoming UDP message — dispatch to server TCOO or client data handler.</summary>
    private void OnUdpMessageReceived(IMessage message)
    {
        if (!IsOpen) return;
        if (message is not CpfConnectedDataMessage cpf) return;

        if (cpf.ConnectionId == _serverTtoOId)
        {
            // Target's TCOO on server connection (response to our produced data)
            OnServerTcooReceived(cpf.Payload);
        }
        else if (cpf.ConnectionId == _clientTtoOId)
        {
            // Target's produced data on client connection
            OnClientDataReceived(cpf.Payload);
        }
        else
        {
            LogMsg($"RX unknown connID=0x{cpf.ConnectionId:X8} len={cpf.Payload.Length} (expecting server TO=0x{_serverTtoOId:X8} client TO=0x{_clientTtoOId:X8})");
        }
    }

    /// <summary>Handle TCOO from target on server connection.</summary>
    private void OnServerTcooReceived(ReadOnlyMemory<byte> data)
    {
        if (!_consumerActive)
        {
            _consumerActive = true;
            _runIdle = true;
            LogMsg($"Consumer active! Transitioning to run=1. TCOO: [{data.Span.ToArray().Select(b => b.ToString("X2")).Aggregate((a,b) => a + " " + b)}]");
        }
    }

    /// <summary>Handle safety data from target on client connection.</summary>
    private void OnClientDataReceived(ReadOnlyMemory<byte> data)
    {
        int wireSize = data.Length;

        // Detect time coordination (6 bytes) vs data
        if (wireSize == 6 || wireSize == 5)
        {
            // Time coordination from target — shouldn't happen on client T→O normally
            return;
        }

        // Decode safety frame
        int dataLen = EstimateDataLength(wireSize, _format);
        if (dataLen <= 0) return;

        // Track the target's 16-bit timestamp and bump _tgtRolloverCount on
        // wrap. CRC-S5 mixes in the full 32-bit timestamp (rollover<<16 |
        // ts), so a missed wrap turns into "CRC fail" for the rest of the
        // connection (after ~65535 * 128us = ~8.4s of run-time).
        ushort incomingTs = SafetyFrameCodec.ExtractTimestamp(data.Span, dataLen, _format);
        if (!_tgtRolloverInitialized)
        {
            _tgtRolloverInitialized = true;
            _tgtLastTs = incomingTs;
        }
        else
        {
            // Raw int subtraction — a wrap shows as a large-magnitude negative.
            int delta = (int)incomingTs - (int)_tgtLastTs;
            if (delta < -0x4000)
                _tgtRolloverCount = (ushort)(_tgtRolloverCount + 1);
            _tgtLastTs = incomingTs;
        }

        var result = SafetyFrameCodec.Decode(data.Span, dataLen, _format,
            _tgtPidSeedS1, _tgtPidSeedS3, _tgtPidSeedS5, _tgtRolloverCount);

        // Extract mode byte
        byte modeByte = dataLen < data.Length ? data.Span[dataLen] : (byte)0;
        byte targetPing = (byte)(modeByte & 0x03);
        bool targetRun = (modeByte & 0x80) != 0;

        // Detect ping count change — send TCOO
        if (_lastTargetPing == 0xFF)
        {
            _lastTargetPing = targetPing;
            SendClientTcoo(targetPing);
        }
        else if (targetPing != _lastTargetPing)
        {
            _lastTargetPing = targetPing;
            SendClientTcoo(targetPing);
        }

        // Fire event with decoded data
        if (result.CrcValid)
        {
            DataReceived?.Invoke(result.ActualData);
            LogMsg($"RX data=[{string.Join(" ", result.ActualData.Select(b => b.ToString("X2")))}] " +
                $"mode=0x{modeByte:X2} run={targetRun} ping={targetPing} " +
                $"crc={result.CrcValid} ts={result.Timestamp}");
        }
        else
        {
            LogMsg($"RX CRC FAIL: {result.ErrorMessage} wire=[{string.Join(" ", data.Span.ToArray().Select(b => b.ToString("X2")))}]");
        }
    }

    /// <summary>Send time coordination on client connection O→T.</summary>
    private void SendClientTcoo(byte pingCountReply)
    {
        if (_serverTargetEndpoint == null) return;

        var buf = new byte[6];
        ushort consumerTime = (ushort)((Environment.TickCount64 * 1000 / 128) & 0xFFFF);

        int len;
        if (_format == SafetyFormat.Extended)
            len = SafetyFrameCodec.EncodeTimeCoordinationExtended(buf, pingCountReply, consumerTime, _cidSeedS5);
        else
            len = SafetyFrameCodec.EncodeTimeCoordination(buf, pingCountReply, consumerTime,
                SafetyCrc.PidCidSeedS3(_origVendor, _origSerial, _targetAppReply.TargetConnectionSerial));

        _udp.SendIoData(_serverTargetEndpoint, _clientOtoTId, _clientEncapSeq, buf.AsSpan(0, len));
        _clientEncapSeq++;

        LogMsg($"TX TCOO ping_reply={pingCountReply} ct={consumerTime}");
    }

    /// <summary>Close both safety connections.</summary>
    public async Task CloseAsync(CancellationToken ct = default)
    {
        IsOpen = false;
        _productionCts?.Cancel();
        _productionCts = null;
        _udp.MessageReceived -= OnUdpMessageReceived;

        // Forward Close server connection
        try
        {
            await SendForwardCloseAsync(_serverConnSerial, ct);
            LogMsg("Server connection closed.");
        }
        catch (Exception ex) { LogMsg($"Server close error: {ex.Message}"); }

        // Forward Close client connection
        try
        {
            await SendForwardCloseAsync(_clientConnSerial, ct);
            LogMsg("Client connection closed.");
        }
        catch (Exception ex) { LogMsg($"Client close error: {ex.Message}"); }
    }

    private async Task SendForwardCloseAsync(ushort connSerial, CancellationToken ct)
    {
        var closeData = new byte[12 + _routePrefix.Length];
        int off = 0;
        closeData[off++] = 0x05; closeData[off++] = 0x9C; // same timing as Forward Open
        BinaryPrimitives.WriteUInt16LittleEndian(closeData.AsSpan(off), connSerial); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(closeData.AsSpan(off), _origVendor); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(closeData.AsSpan(off), _origSerial); off += 4;
        closeData[off++] = (byte)(_routePrefix.Length / 2); // path size in words
        closeData[off++] = 0; // reserved
        _routePrefix.CopyTo(closeData.AsSpan(off));

        var cmPath = new byte[] { 0x20, 0x06, 0x24, 0x01 };
        await _scanner.SendExplicitRawAsync(0x4E, cmPath, closeData, ct);
    }

    public async ValueTask DisposeAsync()
    {
        if (IsOpen)
            await CloseAsync();
    }

    private void LogMsg(string msg) => Log?.Invoke(msg);

    private static int EstimateDataLength(int wireSize, SafetyFormat format)
    {
        int shortDataLen = wireSize - 6;
        if (shortDataLen >= 1 && shortDataLen <= 2)
            return shortDataLen;

        int longDataLen = (wireSize - 8) / 2;
        if (longDataLen >= 3 && longDataLen <= 250 && longDataLen * 2 + 8 == wireSize)
            return longDataLen;

        return -1;
    }
}
