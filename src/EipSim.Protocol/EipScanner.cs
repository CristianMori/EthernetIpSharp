using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EipSim.Cip;

namespace EipSim.Protocol;

/// <summary>
/// EtherNet/IP Scanner (originator/client side).
/// Connects to an adapter (target), registers a session, sends explicit CIP requests,
/// and establishes I/O connections via Forward Open.
/// </summary>
public sealed class EipScanner : IAsyncDisposable
{
    private TcpClient? _client;
    private NetworkStream? _stream;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private EipUdpTransport? _udp;
    private ushort _nextConnSerial = 1;

    public uint SessionHandle { get; private set; }
    public bool IsConnected => _client?.Connected == true && SessionHandle != 0;
    public IPEndPoint? LocalEndpoint { get; private set; }
    public IPEndPoint? RemoteEndpoint { get; private set; }

    /// <summary>Connect to a target device and register a session.</summary>
    public async Task ConnectAsync(IPAddress address, int port = EipAdapter.DefaultPort, CancellationToken ct = default)
    {
        _client = new TcpClient();
        await _client.ConnectAsync(address, port, ct);
        _stream = _client.GetStream();
        LocalEndpoint = (IPEndPoint)_client.Client.LocalEndPoint!;
        RemoteEndpoint = (IPEndPoint)_client.Client.RemoteEndPoint!;

        // Start UDP transport for I/O on ephemeral port
        var udpAddress = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? IPAddress.Loopback : address;
        _udp = new EipUdpTransport(new IPEndPoint(udpAddress, 0));
        await _udp.StartAsync(ct);

        // RegisterSession
        SessionHandle = await RegisterSessionAsync(ct);
    }

    public Task ConnectAsync(string host, int port = EipAdapter.DefaultPort, CancellationToken ct = default)
    {
        var address = Dns.GetHostAddresses(host).First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
        return ConnectAsync(address, port, ct);
    }

    /// <summary>
    /// Send an explicit CIP message (UCMM via SendRRData).
    /// This is the generic transport — any service code, any path, any data.
    /// </summary>
    public async Task<CipServiceResponse> SendExplicitAsync(
        byte serviceCode, byte[] pathBytes, byte[] serviceData, CancellationToken ct = default)
    {
        if (!IsConnected) throw new InvalidOperationException("Not connected");

        // Build MR request
        var mrBuf = new byte[2 + pathBytes.Length + serviceData.Length];
        MrCodec.EncodeRequest(mrBuf, serviceCode, pathBytes, serviceData);

        // Wrap in CPF: Null Address + Unconnected Data
        var cpfBuf = new byte[2048];
        int cpfLen = CpfParser.Write(cpfBuf, [
            new CpfItem { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
            new CpfItem { TypeId = CpfItemType.UnconnectedData, Data = mrBuf },
        ]);

        // SendRRData payload: Interface Handle (4) + Timeout (2) + CPF
        var payload = new byte[6 + cpfLen];
        cpfBuf.AsSpan(0, cpfLen).CopyTo(payload.AsSpan(6));

        // Send and receive
        var responsePayload = await SendEncapsulatedAsync(EncapsulationCommand.SendRRData, payload, ct);

        // Parse response: skip Interface Handle (4) + Timeout (2), then CPF
        var responseCpf = CpfParser.Parse(responsePayload.AsSpan(6));

        // Find unconnected data item
        foreach (var item in responseCpf)
        {
            if (item.TypeId == CpfItemType.UnconnectedData)
            {
                if (!MrCodec.TryParseResponse(item.Data, out var replySvc, out var status, out var respData))
                    throw new InvalidOperationException("Malformed MR response");

                return new CipServiceResponse
                {
                    ServiceCode = replySvc,
                    Status = status,
                    Data = respData,
                };
            }
        }

        throw new InvalidOperationException("No unconnected data in response");
    }

    /// <summary>Establish an I/O connection via Forward Open.</summary>
    public async Task<ScannerConnection> ForwardOpenAsync(ForwardOpenConfig config, CancellationToken ct = default)
    {
        if (!IsConnected) throw new InvalidOperationException("Not connected");

        ushort connSerial = _nextConnSerial++;
        ushort origVendor = 0x0001; // Rockwell
        uint origSerial = (uint)Environment.TickCount;

        // Build connection path: Assembly class, config instance, O→T conn point, T→O conn point
        var connPath = new byte[]
        {
            0x20, 0x04,                        // Class: Assembly
            0x24, (byte)config.ConfigAssembly, // Instance: config
            0x2C, (byte)config.ConsumedAssembly, // Connection Point: O→T
            0x2C, (byte)config.ProducedAssembly, // Connection Point: T→O
        };

        // Connection sizes on wire:
        // O→T (we send): seq(2) + run/idle(4) + data = data + 6. But connection size includes only data after seq.
        // So OT connection size = run/idle(4) + consumedSize
        // T→O (we receive): seq(2) + data. Connection size = producedSize
        ushort otConnSize = (ushort)(4 + config.ConsumedSize); // includes run/idle header
        ushort toConnSize = config.ProducedSize;

        // Network params: P2P, variable size
        ushort otParams = (ushort)(0x4200 | (otConnSize & 0x01FF)); // P2P + variable
        ushort toParams = (ushort)(0x4200 | (toConnSize & 0x01FF)); // P2P + variable

        // For P2P: originator chooses T→O conn ID, target chooses O→T conn ID
        uint toConnId = (uint)(0x10000000 | connSerial);

        // Build Forward Open data
        var fwdOpenData = new byte[36 + connPath.Length];
        int off = 0;
        fwdOpenData[off++] = 0x0A; // Priority/Time_tick
        fwdOpenData[off++] = 0x05; // Timeout_ticks
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), 0); off += 4; // OT conn ID (target chooses)
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), toConnId); off += 4; // TO conn ID (we choose)
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), connSerial); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), origVendor); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), origSerial); off += 4;
        fwdOpenData[off++] = config.TimeoutMultiplier;
        off += 3; // Reserved
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), config.Rpi); off += 4; // OT RPI
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), otParams); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(fwdOpenData.AsSpan(off), config.Rpi); off += 4; // TO RPI
        BinaryPrimitives.WriteUInt16LittleEndian(fwdOpenData.AsSpan(off), toParams); off += 2;
        fwdOpenData[off++] = config.TransportClass; // Class 0/1, cyclic, server
        fwdOpenData[off++] = (byte)(connPath.Length / 2);
        connPath.CopyTo(fwdOpenData.AsSpan(off));

        // Send as explicit message to Connection Manager (class 0x06, instance 1)
        var cmPath = new byte[] { 0x20, 0x06, 0x24, 0x01 };
        var (response, cpfItems) = await SendExplicitRawAsync(0x54, cmPath, fwdOpenData, ct);

        if (!response.Status.IsSuccess)
            throw new InvalidOperationException(
                $"Forward Open failed: status=0x{response.Status.GeneralStatus:X2}");

        // Parse response: OT conn ID (4) + TO conn ID (4) + ...
        var respData = response.Data.ToArray();
        uint respOtConnId = BinaryPrimitives.ReadUInt32LittleEndian(respData);
        uint respToConnId = BinaryPrimitives.ReadUInt32LittleEndian(respData.AsSpan(4));

        // Get target's UDP endpoint from Sockaddr Info O→T item
        int targetUdpPort = EipUdpTransport.IoPort;
        IPAddress targetUdpAddr = RemoteEndpoint!.Address;
        foreach (var cpfItem in cpfItems)
        {
            if (cpfItem.TypeId == CpfItemType.SockaddrInfoOtoT && cpfItem.Data.Length >= 8)
            {
                targetUdpPort = BinaryPrimitives.ReadUInt16BigEndian(cpfItem.Data.Span.Slice(2));
                var addrBytes = cpfItem.Data.Slice(4, 4).ToArray();
                var sockAddr = new IPAddress(addrBytes);
                if (!sockAddr.Equals(IPAddress.Any))
                    targetUdpAddr = sockAddr;
                break;
            }
        }
        // Ensure IPv4 — UDP socket is IPv4
        if (targetUdpAddr.IsIPv4MappedToIPv6)
            targetUdpAddr = targetUdpAddr.MapToIPv4();
        var targetUdpEndpoint = new IPEndPoint(targetUdpAddr, targetUdpPort);

        var scannerConn = new ScannerConnection(
            this, _udp!, config, targetUdpEndpoint,
            otoTConnectionId: respOtConnId,  // Target assigned — ID we use in our O→T sends
            ttoOConnectionId: respToConnId,  // Should match our toConnId — ID target uses in T→O sends
            connectionSerial: connSerial,
            originatorVendor: origVendor,
            originatorSerial: origSerial);

        scannerConn.Start();
        return scannerConn;
    }

    /// <summary>Send explicit CIP and return both the MR response and all CPF items (for Sockaddr Info etc.).</summary>
    private async Task<(CipServiceResponse response, CpfItem[] cpfItems)> SendExplicitRawAsync(
        byte serviceCode, byte[] pathBytes, byte[] serviceData, CancellationToken ct)
    {
        if (!IsConnected) throw new InvalidOperationException("Not connected");

        var mrBuf = new byte[2 + pathBytes.Length + serviceData.Length];
        MrCodec.EncodeRequest(mrBuf, serviceCode, pathBytes, serviceData);

        var cpfBuf = new byte[2048];
        int cpfLen = CpfParser.Write(cpfBuf, [
            new CpfItem { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
            new CpfItem { TypeId = CpfItemType.UnconnectedData, Data = mrBuf },
        ]);

        var payload = new byte[6 + cpfLen];
        cpfBuf.AsSpan(0, cpfLen).CopyTo(payload.AsSpan(6));

        var responsePayload = await SendEncapsulatedAsync(EncapsulationCommand.SendRRData, payload, ct);
        var responseCpf = CpfParser.Parse(responsePayload.AsSpan(6));

        CipServiceResponse? response = null;
        foreach (var item in responseCpf)
        {
            if (item.TypeId == CpfItemType.UnconnectedData)
            {
                if (!MrCodec.TryParseResponse(item.Data, out var replySvc, out var status, out var respData))
                    throw new InvalidOperationException("Malformed MR response");

                response = new CipServiceResponse
                {
                    ServiceCode = replySvc,
                    Status = status,
                    Data = respData,
                };
            }
        }

        if (response == null)
            throw new InvalidOperationException("No unconnected data in response");

        return (response.Value, responseCpf);
    }

    /// <summary>Send Forward Close for a connection.</summary>
    internal async Task ForwardCloseAsync(ushort connSerial, ushort origVendor, uint origSerial,
        CancellationToken ct = default)
    {
        var closeData = new byte[12];
        int off = 0;
        closeData[off++] = 0x0A; closeData[off++] = 0x05;
        BinaryPrimitives.WriteUInt16LittleEndian(closeData.AsSpan(off), connSerial); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(closeData.AsSpan(off), origVendor); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(closeData.AsSpan(off), origSerial); off += 4;
        closeData[off++] = 0; // path size
        closeData[off++] = 0; // reserved

        var cmPath = new byte[] { 0x20, 0x06, 0x24, 0x01 };
        await SendExplicitAsync(0x4E, cmPath, closeData, ct);
    }

    /// <summary>Disconnect: unregister session and close TCP.</summary>
    public async Task DisconnectAsync()
    {
        if (_stream != null && SessionHandle != 0)
        {
            try
            {
                var header = new EncapsulationHeader
                {
                    Command = EncapsulationCommand.UnregisterSession,
                    SessionHandle = SessionHandle,
                };
                var buf = new byte[EncapsulationHeader.Size];
                header.WriteTo(buf);
                await _stream.WriteAsync(buf);
            }
            catch { }
        }

        SessionHandle = 0;
        _stream?.Dispose();
        _client?.Dispose();
    }

    // --- Private helpers ---

    private async Task<uint> RegisterSessionAsync(CancellationToken ct)
    {
        var payload = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(payload, 1); // Protocol version
        // Options = 0

        var response = await SendEncapsulatedAsync(EncapsulationCommand.RegisterSession, payload, ct);
        // Response payload is protocol version (2) + options (2), session handle is in the header
        // We need the header — let's re-read it from the last received header
        return _lastResponseHeader.SessionHandle;
    }

    private EncapsulationHeader _lastResponseHeader;

    private async Task<byte[]> SendEncapsulatedAsync(EncapsulationCommand command, byte[] payload,
        CancellationToken ct)
    {
        await _sendLock.WaitAsync(ct);
        try
        {
            var header = new EncapsulationHeader
            {
                Command = command,
                Length = (ushort)payload.Length,
                SessionHandle = SessionHandle,
            };

            var buf = new byte[EncapsulationHeader.Size + payload.Length];
            header.WriteTo(buf);
            payload.CopyTo(buf.AsSpan(EncapsulationHeader.Size));
            await _stream!.WriteAsync(buf, ct);

            // Read response header
            var respHeaderBuf = new byte[EncapsulationHeader.Size];
            await ReadExactAsync(_stream, respHeaderBuf, ct);
            _lastResponseHeader = EncapsulationHeader.Parse(respHeaderBuf);

            if (_lastResponseHeader.Status != EncapsulationStatus.Success)
                throw new InvalidOperationException(
                    $"Encapsulation error: command={command}, status={_lastResponseHeader.Status}");

            // Read response payload
            byte[] respPayload = [];
            if (_lastResponseHeader.Length > 0)
            {
                respPayload = new byte[_lastResponseHeader.Length];
                await ReadExactAsync(_stream, respPayload, ct);
            }

            return respPayload;
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) throw new IOException("Connection closed");
            read += n;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_udp != null) await _udp.DisposeAsync();
        await DisconnectAsync();
        _sendLock.Dispose();
    }
}
