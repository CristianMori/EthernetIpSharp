using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EipSim.Cip;

namespace EipSim.Protocol;

/// <summary>
/// EtherNet/IP Adapter (server/target side).
/// Listens on TCP port 44818 for encapsulation commands from scanners/originators.
/// Routes CIP explicit messages through ICipDispatch.
/// Handles session management, ListIdentity, ListServices, and Forward Open/Close detection.
/// </summary>
public sealed class EipAdapter : IAsyncDisposable
{
    /// <summary>Standard EtherNet/IP TCP port (0xAF12).</summary>
    public const int DefaultPort = 44818;

    private readonly ICipDispatch _dispatch;
    private readonly ISessionManager _sessions;
    private readonly IdentityInfo _identity;
    private readonly ICipDispatch? _identitySource;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    /// <summary>The TCP port this adapter is listening on.</summary>
    public int Port { get; private set; }

    /// <summary>The UDP port this adapter's device listens on for I/O data. Set by VirtualDevice.</summary>
    public int UdpPort { get; set; } = EipUdpTransport.IoPort;

    /// <summary>
    /// Fired when a successful Forward Open response is about to be sent.
    /// Parameters: CIP service response, remote scanner UDP endpoint.
    /// Used by VirtualDevice to set RemoteEndpoint on the new IoConnection.
    /// </summary>
    public event Action<CipServiceResponse, IPEndPoint>? ConnectionOpened;

    /// <summary>Convenience constructor using default SessionManager.</summary>
    public EipAdapter(ICipDispatch dispatch, IdentityInfo identity, ICipDispatch? identitySource = null)
        : this(dispatch, identity, new SessionManager(), identitySource) { }

    /// <summary>DI constructor — inject session manager (or mock).</summary>
    public EipAdapter(ICipDispatch dispatch, IdentityInfo identity, ISessionManager sessions, ICipDispatch? identitySource = null)
    {
        _dispatch = dispatch;
        _identity = identity;
        _sessions = sessions;
        _identitySource = identitySource ?? dispatch;
    }

    /// <summary>Start listening for TCP connections on the given endpoint.</summary>
    public async Task ListenAsync(IPEndPoint endpoint, CancellationToken ct = default)
    {
        Port = endpoint.Port;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _listener = new TcpListener(endpoint);
        _listener.Start();
        _ = AcceptLoopAsync(_cts.Token);
    }

    /// <summary>Start listening on the given address and port.</summary>
    public Task ListenAsync(IPAddress address, int port = DefaultPort, CancellationToken ct = default) =>
        ListenAsync(new IPEndPoint(address, port), ct);

    /// <summary>Accept loop — runs until cancelled. Spawns a task per client connection.</summary>
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

    /// <summary>
    /// Per-client connection handler. Reads encapsulation messages in a loop
    /// until the client disconnects or cancellation is requested.
    /// </summary>
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

                    if (response != null)
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

    /// <summary>Dispatch an encapsulation command to the appropriate handler. Returns null for no-reply commands.</summary>
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

    /// <summary>
    /// Handle ListIdentity — return device identity in CIP Identity CPF item.
    /// Socket address fields are big-endian per the spec.
    /// </summary>
    private byte[] HandleListIdentity(EncapsulationHeader header, IPEndPoint localEndpoint)
    {
        var identityData = new byte[512];
        int offset = 0;

        // Encapsulation protocol version
        BinaryPrimitives.WriteUInt16LittleEndian(identityData.AsSpan(offset), 1); offset += 2;
        // Socket address (big-endian)
        BinaryPrimitives.WriteInt16BigEndian(identityData.AsSpan(offset), 2); offset += 2; // sin_family = AF_INET
        BinaryPrimitives.WriteUInt16BigEndian(identityData.AsSpan(offset), (ushort)Port); offset += 2; // sin_port
        localEndpoint.Address.GetAddressBytes().CopyTo(identityData.AsSpan(offset)); offset += 4; // sin_addr
        identityData.AsSpan(offset, 8).Clear(); offset += 8; // sin_zero

        // Identity attributes from GetAttributeAll on Identity object instance 1
        var identityPath = new CipPath { ClassId = IdentityInfo.ClassCode, InstanceId = 1 };
        var getAll = _identitySource!.Dispatch(CipStandardServices.GetAttributeAll, identityPath, ReadOnlyMemory<byte>.Empty);
        if (getAll.Status.IsSuccess && !getAll.Data.IsEmpty)
        {
            getAll.Data.Span.CopyTo(identityData.AsSpan(offset));
            offset += getAll.Data.Length;
        }

        // State attribute (0xFF = not implemented)
        identityData[offset++] = 0xFF;

        var cpfBuf = new byte[1024];
        var identityItem = new CpfItem { TypeId = CpfItemType.CipIdentity, Data = identityData.AsMemory(0, offset) };
        int cpfLen = CpfParser.Write(cpfBuf, [identityItem]);

        return BuildResponse(header, cpfBuf.AsSpan(0, cpfLen));
    }

    /// <summary>Handle ListServices — return the Communications service capability.</summary>
    private static byte[] HandleListServices(EncapsulationHeader header)
    {
        var serviceData = new byte[20];
        int offset = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(serviceData.AsSpan(offset), 1); offset += 2; // Version
        BinaryPrimitives.WriteUInt16LittleEndian(serviceData.AsSpan(offset), 0x0120); offset += 2; // Capability flags
        "Communications\0\0"u8.Slice(0, 16).CopyTo(serviceData.AsSpan(offset)); offset += 16; // Name (16 bytes padded)

        var cpfBuf = new byte[256];
        var serviceItem = new CpfItem { TypeId = CpfItemType.ListServicesResponse, Data = serviceData.AsMemory(0, offset) };
        int cpfLen = CpfParser.Write(cpfBuf, [serviceItem]);

        return BuildResponse(header, cpfBuf.AsSpan(0, cpfLen));
    }

    /// <summary>Handle RegisterSession — allocate a session handle and return it.</summary>
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
            Status = EncapsulationStatus.Success,
            SenderContext = header.SenderContext,
        };

        var buf = new byte[EncapsulationHeader.Size + 4];
        reply.WriteTo(buf);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(EncapsulationHeader.Size), 1); // Protocol version
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(EncapsulationHeader.Size + 2), 0); // Options
        return buf;
    }

    /// <summary>Handle UnregisterSession — release the session. No reply sent (returns null).</summary>
    private byte[]? HandleUnregisterSession(EncapsulationHeader header, ref uint sessionHandle)
    {
        _sessions.Unregister(header.SessionHandle);
        sessionHandle = 0;
        return null;
    }

    /// <summary>
    /// Handle SendRRData — route an unconnected explicit message through ICipDispatch.
    /// Detects successful Forward Open responses and appends Sockaddr Info items.
    /// </summary>
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
        if (!MrCodec.TryParseRequest(dataItem.Value.Data, out var serviceCode, out var path, out var data))
            return BuildErrorResponse(header, EncapsulationStatus.IncorrectData);

        var cipResponse = _dispatch.Dispatch(serviceCode, path, data);

        // Encode MR response using pooled buffer
        var mrResponseBuf = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            int mrLen = cipResponse.Encode(mrResponseBuf);

            // Build reply CPF items — pre-size for potential Sockaddr Info items
            bool isForwardOpen = cipResponse.Status.IsSuccess &&
                                 (serviceCode == 0x54 || serviceCode == 0x5B);
            var replyItems = isForwardOpen ? new CpfItem[4] : new CpfItem[2];
            int itemCount = 0;

            replyItems[itemCount++] = new CpfItem { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty };
            replyItems[itemCount++] = new CpfItem { TypeId = CpfItemType.UnconnectedData, Data = mrResponseBuf.AsMemory(0, mrLen) };

            if (isForwardOpen)
            {
                // Sockaddr Info O→T: tells scanner where to send O→T data (our UDP port)
                replyItems[itemCount++] = new CpfItem { TypeId = CpfItemType.SockaddrInfoOtoT, Data = BuildSockaddrInfo(localEp.Address, UdpPort) };
                // Sockaddr Info T→O: where we'll send T→O data
                replyItems[itemCount++] = new CpfItem { TypeId = CpfItemType.SockaddrInfoTtoO, Data = BuildSockaddrInfo(IPAddress.Any, UdpPort) };

                // Notify VirtualDevice to set RemoteEndpoint on the new connection
                var plcUdpEndpoint = new IPEndPoint(remoteEp.Address, EipUdpTransport.IoPort);
                ConnectionOpened?.Invoke(cipResponse, plcUdpEndpoint);
            }

            var replyCpfBuf = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                int replyCpfLen = CpfParser.Write(replyCpfBuf, replyItems.AsSpan(0, itemCount));

                var responsePayload = new byte[6 + replyCpfLen];
                replyCpfBuf.AsSpan(0, replyCpfLen).CopyTo(responsePayload.AsSpan(6));

                return BuildResponse(header, responsePayload, sessionHandle);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(replyCpfBuf);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(mrResponseBuf);
        }
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

    /// <summary>Build a success response with the given payload.</summary>
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

    /// <summary>Build an error response with no payload.</summary>
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

    /// <summary>Read exactly buffer.Length bytes from the stream. Returns 0 if connection closed.</summary>
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

    /// <summary>Stop listening and release resources.</summary>
    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _cts?.Dispose();
    }
}
