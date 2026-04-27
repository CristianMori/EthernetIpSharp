using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EipSim.Cip;

namespace EipSim.Protocol;

/// <summary>
/// EtherNet/IP Adapter (server/target side).
/// Listens on TCP for encapsulation commands, routes CIP requests through ICipDispatch.
/// </summary>
public sealed class EipAdapter : IAsyncDisposable
{
    public const int DefaultPort = 44818; // 0xAF12

    private readonly ICipDispatch _dispatch;
    private readonly ISessionManager _sessions;
    private readonly IdentityInfo _identity;
    private readonly ICipDispatch? _identitySource;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    public int Port { get; private set; }

    /// <summary>The UDP port this adapter's device listens on for I/O data. Set by VirtualDevice.</summary>
    public int UdpPort { get; set; } = EipUdpTransport.IoPort;

    /// <summary>
    /// Called when a new connection is established via Forward Open.
    /// The adapter sets the remote endpoint (PLC IP + UDP port) on the connection object
    /// so that T→O production can send to the right place.
    /// Signature: (IoConnection connection, IPEndPoint remoteEndpoint)
    /// </summary>
    public event Action<object, IPEndPoint>? ConnectionOpened;

    public EipAdapter(ICipDispatch dispatch, IdentityInfo identity, ICipDispatch? identitySource = null)
        : this(dispatch, identity, new SessionManager(), identitySource) { }

    public EipAdapter(ICipDispatch dispatch, IdentityInfo identity, ISessionManager sessions, ICipDispatch? identitySource = null)
    {
        _dispatch = dispatch;
        _identity = identity;
        _sessions = sessions;
        _identitySource = identitySource ?? dispatch;
    }

    public async Task ListenAsync(IPEndPoint endpoint, CancellationToken ct = default)
    {
        Port = endpoint.Port;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _listener = new TcpListener(endpoint);
        _listener.Start();
        _ = AcceptLoopAsync(_cts.Token);
    }

    public Task ListenAsync(IPAddress address, int port = DefaultPort, CancellationToken ct = default) =>
        ListenAsync(new IPEndPoint(address, port), ct);

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(ct);
                _ = HandleClientAsync(client, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            var stream = client.GetStream();
            var headerBuf = new byte[EncapsulationHeader.Size];
            uint sessionHandle = 0;
            var localEp = (IPEndPoint)client.Client.LocalEndPoint!;
            var remoteEp = (IPEndPoint)client.Client.RemoteEndPoint!;

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    int read = await ReadExactAsync(stream, headerBuf, ct);
                    if (read == 0) break;

                    var header = EncapsulationHeader.Parse(headerBuf);

                    byte[] payload = [];
                    if (header.Length > 0)
                    {
                        payload = new byte[header.Length];
                        if (await ReadExactAsync(stream, payload, ct) == 0) break;
                    }

                    var response = HandleCommand(header, payload, ref sessionHandle, localEp, remoteEp);

                    if (response != null && response.Length > 0)
                        await stream.WriteAsync(response, ct);
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            finally
            {
                if (sessionHandle != 0)
                    _sessions.Unregister(sessionHandle);
            }
        }
    }

    private byte[]? HandleCommand(EncapsulationHeader header, byte[] payload,
        ref uint sessionHandle, IPEndPoint localEp, IPEndPoint remoteEp)
    {
        return header.Command switch
        {
            EncapsulationCommand.Nop => null,
            EncapsulationCommand.ListIdentity => HandleListIdentity(header, localEp),
            EncapsulationCommand.ListServices => HandleListServices(header),
            EncapsulationCommand.RegisterSession => HandleRegisterSession(header, ref sessionHandle),
            EncapsulationCommand.UnregisterSession => HandleUnregisterSession(header, ref sessionHandle),
            EncapsulationCommand.SendRRData => HandleSendRRData(header, payload, sessionHandle, localEp, remoteEp),
            _ => BuildErrorResponse(header, EncapsulationStatus.InvalidCommand),
        };
    }

    private byte[] HandleListIdentity(EncapsulationHeader header, IPEndPoint localEndpoint)
    {
        var identityData = new byte[512];
        int offset = 0;

        BinaryPrimitives.WriteUInt16LittleEndian(identityData.AsSpan(offset), 1); offset += 2;
        BinaryPrimitives.WriteInt16BigEndian(identityData.AsSpan(offset), 2); offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(identityData.AsSpan(offset), (ushort)Port); offset += 2;
        localEndpoint.Address.GetAddressBytes().CopyTo(identityData.AsSpan(offset)); offset += 4;
        identityData.AsSpan(offset, 8).Clear(); offset += 8;

        var identityPath = new CipPath { ClassId = IdentityInfo.ClassCode, InstanceId = 1 };
        var getAll = _identitySource!.Dispatch(CipStandardServices.GetAttributeAll, identityPath, ReadOnlyMemory<byte>.Empty);
        if (getAll.Status.IsSuccess && !getAll.Data.IsEmpty)
        {
            getAll.Data.Span.CopyTo(identityData.AsSpan(offset));
            offset += getAll.Data.Length;
        }

        identityData[offset++] = 0xFF;

        var cpfBuf = new byte[1024];
        var identityItem = new CpfItem { TypeId = CpfItemType.CipIdentity, Data = identityData.AsMemory(0, offset) };
        int cpfLen = CpfParser.Write(cpfBuf, [identityItem]);

        return BuildResponse(header, cpfBuf.AsSpan(0, cpfLen));
    }

    private static byte[] HandleListServices(EncapsulationHeader header)
    {
        var serviceData = new byte[20];
        int offset = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(serviceData.AsSpan(offset), 1); offset += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(serviceData.AsSpan(offset), 0x0120); offset += 2;
        "Communications\0\0"u8.Slice(0, 16).CopyTo(serviceData.AsSpan(offset)); offset += 16;

        var cpfBuf = new byte[256];
        var serviceItem = new CpfItem { TypeId = CpfItemType.ListServicesResponse, Data = serviceData.AsMemory(0, offset) };
        int cpfLen = CpfParser.Write(cpfBuf, [serviceItem]);

        return BuildResponse(header, cpfBuf.AsSpan(0, cpfLen));
    }

    private byte[] HandleRegisterSession(EncapsulationHeader header, ref uint sessionHandle)
    {
        if (sessionHandle != 0)
            return BuildErrorResponse(header, EncapsulationStatus.InvalidCommand);

        sessionHandle = _sessions.Register();

        var reply = new EncapsulationHeader
        {
            Command = EncapsulationCommand.RegisterSession,
            Length = 4,
            SessionHandle = sessionHandle,
            Status = 0,
            SenderContext = header.SenderContext,
        };

        var buf = new byte[EncapsulationHeader.Size + 4];
        reply.WriteTo(buf);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(EncapsulationHeader.Size), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(EncapsulationHeader.Size + 2), 0);
        return buf;
    }

    private byte[] HandleUnregisterSession(EncapsulationHeader header, ref uint sessionHandle)
    {
        _sessions.Unregister(header.SessionHandle);
        sessionHandle = 0;
        return [];
    }

    private byte[] HandleSendRRData(EncapsulationHeader header, byte[] payload,
        uint sessionHandle, IPEndPoint localEp, IPEndPoint remoteEp)
    {
        if (sessionHandle == 0 || !_sessions.IsValid(header.SessionHandle))
            return BuildErrorResponse(header, EncapsulationStatus.InvalidSessionHandle);

        if (payload.Length < 6)
            return BuildErrorResponse(header, EncapsulationStatus.IncorrectData);

        var cpfData = payload.AsSpan(6);
        var items = CpfParser.Parse(cpfData);

        CpfItem? dataItem = null;
        foreach (var item in items)
            if (item.TypeId == CpfItemType.UnconnectedData) { dataItem = item; break; }

        if (dataItem == null)
            return BuildErrorResponse(header, EncapsulationStatus.IncorrectData);

        // Parse MR request and dispatch
        var (serviceCode, path, data) = MrCodec.ParseRequest(dataItem.Value.Data);
        var cipResponse = _dispatch.Dispatch(serviceCode, path, data);

        // Encode MR response
        var mrResponseBuf = new byte[4096];
        int mrLen = cipResponse.Encode(mrResponseBuf);

        // Build reply CPF items
        var replyItemsList = new List<CpfItem>
        {
            new() { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
            new() { TypeId = CpfItemType.UnconnectedData, Data = mrResponseBuf.AsMemory(0, mrLen) },
        };

        // If this was a successful Forward Open (0x54 or 0x5B), append Sockaddr Info items
        // and notify the adapter so it can set RemoteEndpoint on the connection
        if (cipResponse.Status.IsSuccess &&
            (serviceCode == 0x54 || serviceCode == 0x5B))
        {
            // Sockaddr Info O→T (0x8000): tells scanner where to send O→T data (our UDP port)
            var sockOtoT = BuildSockaddrInfo(localEp.Address, UdpPort);
            replyItemsList.Add(new CpfItem { TypeId = CpfItemType.SockaddrInfoOtoT, Data = sockOtoT });

            // Sockaddr Info T→O (0x8001): where we'll send T→O data
            var sockTtoO = BuildSockaddrInfo(IPAddress.Any, UdpPort);
            replyItemsList.Add(new CpfItem { TypeId = CpfItemType.SockaddrInfoTtoO, Data = sockTtoO });

            // Set RemoteEndpoint — assume scanner listens on the standard port
            var plcUdpEndpoint = new IPEndPoint(remoteEp.Address, EipUdpTransport.IoPort);
            ConnectionOpened?.Invoke(cipResponse, plcUdpEndpoint);
        }

        var replyCpfBuf = new byte[4096];
        int replyCpfLen = CpfParser.Write(replyCpfBuf, replyItemsList.ToArray());

        var responsePayload = new byte[6 + replyCpfLen];
        replyCpfBuf.AsSpan(0, replyCpfLen).CopyTo(responsePayload.AsSpan(6));

        return BuildResponse(header, responsePayload, sessionHandle);
    }

    /// <summary>Build a 16-byte sockaddr_in structure (big-endian for socket fields).</summary>
    private static byte[] BuildSockaddrInfo(IPAddress address, int port)
    {
        var data = new byte[16];
        BinaryPrimitives.WriteInt16BigEndian(data, 2); // sin_family = AF_INET
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2), (ushort)port); // sin_port
        address.GetAddressBytes().CopyTo(data.AsSpan(4)); // sin_addr
        // sin_zero (8 bytes) already zeroed
        return data;
    }

    private static byte[] BuildResponse(EncapsulationHeader req, ReadOnlySpan<byte> payload, uint? session = null)
    {
        var reply = new EncapsulationHeader
        {
            Command = req.Command,
            Length = (ushort)payload.Length,
            SessionHandle = session ?? req.SessionHandle,
            SenderContext = req.SenderContext,
        };
        var buf = new byte[EncapsulationHeader.Size + payload.Length];
        reply.WriteTo(buf);
        payload.CopyTo(buf.AsSpan(EncapsulationHeader.Size));
        return buf;
    }

    private static byte[] BuildErrorResponse(EncapsulationHeader req, EncapsulationStatus status)
    {
        var reply = new EncapsulationHeader
        {
            Command = req.Command,
            SessionHandle = req.SessionHandle,
            Status = status,
            SenderContext = req.SenderContext,
        };
        var buf = new byte[EncapsulationHeader.Size];
        reply.WriteTo(buf);
        return buf;
    }

    private static async Task<int> ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(totalRead), ct);
            if (n == 0) return 0;
            totalRead += n;
        }
        return totalRead;
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _cts?.Dispose();
    }
}
