using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Protocol.Messages;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// EtherNet/IP Adapter (server/target side).
/// Listens on TCP port 44818 for encapsulation commands from scanners/originators.
/// Routes CIP explicit messages through ICipDispatch.
/// Handles session management, ListIdentity, ListServices, and Forward Open/Close detection.
///
/// Base class is Class-3-clean by default: Forward Open replies carry only the
/// standard NullAddress + UnconnectedData CPF items. Use the
/// <see cref="IoEipAdapter"/> subclass when serving Class 0/1 I/O connections
/// that need Sockaddr Info O→T / T→O items on the reply.
/// </summary>
public class EipAdapter : IAsyncDisposable
{
    /// <summary>Standard EtherNet/IP TCP port (0xAF12).</summary>
    public const int DefaultPort = 44818;

    private readonly ICipDispatch _dispatch;
    private readonly ISessionManager _sessions;
    private readonly IdentityInfo _identity;
    private readonly ICipDispatch? _identitySource;
    private readonly TcpSocket _socket = new();
    private readonly EncapsulationMessageManager _manager = new();

    /// <summary>The TCP port this adapter is listening on.</summary>
    public int Port { get; private set; }

    /// <summary>
    /// SendUnitData reply requires the reverse of the connection ID the PLC sent
    /// in: PLC ships with OT_conn_id (we assigned), we must reply with TO_conn_id
    /// (PLC assigned). Wire this to ConnectionManager's <c>FindByOtoTId</c> lookup.
    /// If unset, the reply echoes the request's connection_id — fine for loopback
    /// tests but rejected by Logix MSG instructions (which see "not for me" and
    /// time out).
    /// </summary>
    public Func<uint, uint>? ConnectionIdLookup { get; set; }

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
    public Task ListenAsync(IPEndPoint endpoint, CancellationToken ct = default)
    {
        Port = endpoint.Port;
        _socket.ClientConnected += OnClientConnected;
        return _socket.StartAsync(endpoint, ct);
    }

    /// <summary>Start listening on the given address and port.</summary>
    public Task ListenAsync(IPAddress address, int port = DefaultPort, CancellationToken ct = default) =>
        ListenAsync(new IPEndPoint(address, port), ct);

    /// <summary>
    /// Wire up per-client state: a byte accumulator (in case messages span
    /// multiple receives) and the per-session handle for RegisterSession.
    /// All session state lives in the closure — no shared mutable state.
    /// </summary>
    private void OnClientConnected(TcpSocketConnection conn)
    {
        var accum = new TcpFrameAccumulator();
        uint sessionHandle = 0;

        conn.BytesReceived += (c, chunk) =>
        {
            accum.Append(chunk.Span);
            while (true)
            {
                var msg = _manager.TryParse(accum.GetReadableBytes(), c.RemoteEndpoint, out int consumed);
                if (msg == null) break; // need more bytes
                accum.Advance(consumed);

                var response = DispatchMessage(msg, ref sessionHandle, c.LocalEndpoint, c.RemoteEndpoint);
                if (response != null) c.Send(response);
            }
        };
        conn.Closed += c =>
        {
            if (sessionHandle != 0) _sessions.Unregister(sessionHandle);
        };
    }

    /// <summary>Dispatch a typed encapsulation message to the appropriate handler.</summary>
    private byte[]? DispatchMessage(IMessage msg, ref uint sessionHandle, IPEndPoint localEp, IPEndPoint remoteEp)
    {
        switch (msg)
        {
            case NopMessage: return null;
            case ListIdentityMessage li:     return HandleListIdentity(li, localEp);
            case ListServicesMessage ls:     return HandleListServices(ls);
            case RegisterSessionMessage rs:  return HandleRegisterSession(rs, ref sessionHandle);
            case UnregisterSessionMessage us:return HandleUnregisterSession(us, ref sessionHandle);
            case SendRRDataMessage rr:       return HandleSendRRData(rr, sessionHandle, localEp, remoteEp);
            case SendUnitDataMessage su:     return HandleSendUnitData(su, sessionHandle);
            case EncapsulationMessage raw:   return BuildErrorResponse(raw.Header.Command, raw.Header.SessionHandle, raw.Header.SenderContext, EncapsulationStatus.InvalidCommand);
            default: return null;
        }
    }

    /// <summary>
    /// Handle ListIdentity — return device identity in CIP Identity CPF item.
    /// Socket address fields are big-endian.
    /// </summary>
    private byte[] HandleListIdentity(ListIdentityMessage msg, IPEndPoint localEndpoint)
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

        return BuildResponse(EncapsulationCommand.ListIdentity, msg.SessionHandle, msg.SenderContext, cpfBuf.AsSpan(0, cpfLen));
    }

    /// <summary>Handle ListServices — return the Communications service capability.</summary>
    private static byte[] HandleListServices(ListServicesMessage msg)
    {
        var serviceData = new byte[20];
        int offset = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(serviceData.AsSpan(offset), 1); offset += 2; // Version
        BinaryPrimitives.WriteUInt16LittleEndian(serviceData.AsSpan(offset), 0x0120); offset += 2; // Capability flags
        "Communications\0\0"u8.Slice(0, 16).CopyTo(serviceData.AsSpan(offset)); offset += 16; // Name (16 bytes padded)

        var cpfBuf = new byte[256];
        var serviceItem = new CpfItem { TypeId = CpfItemType.ListServicesResponse, Data = serviceData.AsMemory(0, offset) };
        int cpfLen = CpfParser.Write(cpfBuf, [serviceItem]);

        return BuildResponse(EncapsulationCommand.ListServices, msg.SessionHandle, msg.SenderContext, cpfBuf.AsSpan(0, cpfLen));
    }

    /// <summary>Handle RegisterSession — allocate a session handle and return it.</summary>
    private byte[] HandleRegisterSession(RegisterSessionMessage msg, ref uint sessionHandle)
    {
        if (sessionHandle != 0)
            return BuildErrorResponse(EncapsulationCommand.RegisterSession, msg.SessionHandle, msg.SenderContext, EncapsulationStatus.InvalidCommand);

        sessionHandle = _sessions.Register();

        var reply = new RegisterSessionMessage
        {
            SessionHandle = sessionHandle,
            Status = EncapsulationStatus.Success,
            SenderContext = msg.SenderContext,
            ProtocolVersion = 1,
            OptionsFlags = 0,
            RemoteEndpoint = msg.RemoteEndpoint,
        };
        var buf = new byte[reply.WireSize];
        reply.WriteTo(buf);
        return buf;
    }

    /// <summary>Handle UnregisterSession — release the session. No reply sent (returns null).</summary>
    private byte[]? HandleUnregisterSession(UnregisterSessionMessage msg, ref uint sessionHandle)
    {
        _sessions.Unregister(msg.SessionHandle);
        sessionHandle = 0;
        return null;
    }

    /// <summary>
    /// Handle SendRRData — route an unconnected explicit message through ICipDispatch.
    /// Detects successful Forward Open responses and appends Sockaddr Info items.
    /// </summary>
    private byte[] HandleSendUnitData(SendUnitDataMessage msg, uint sessionHandle)
    {
        // Connected explicit messaging (Class 3). After Forward Open opens a
        // Class 3 connection, pycomm3 sends every subsequent CIP request via
        // SendUnitData (0x70) instead of SendRRData. Without this handler
        // those requests are silently dropped and the client times out.
        //
        // ConnectedData payload = sequence_count(2) + MR request. Echo the
        // sequence in the reply.
        if (sessionHandle == 0 || !_sessions.IsValid(msg.SessionHandle))
            return BuildErrorResponse(EncapsulationCommand.SendUnitData, msg.SessionHandle, msg.SenderContext, EncapsulationStatus.InvalidSessionHandle);

        if (msg.CipData.Length < 2)
            return BuildErrorResponse(EncapsulationCommand.SendUnitData, msg.SessionHandle, msg.SenderContext, EncapsulationStatus.IncorrectData);

        ushort seqCount = BinaryPrimitives.ReadUInt16LittleEndian(msg.CipData.Span);
        var mrIn = msg.CipData[2..];

        if (!MrCodec.TryParseRequest(mrIn, out var serviceCode, out var path, out var data))
            return BuildErrorResponse(EncapsulationCommand.SendUnitData, msg.SessionHandle, msg.SenderContext, EncapsulationStatus.IncorrectData);

        var cipResponse = _dispatch.Dispatch(serviceCode, path, data);

        var mrBuf = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            int mrLen = cipResponse.Encode(mrBuf);
            var cipData = new byte[2 + mrLen];
            BinaryPrimitives.WriteUInt16LittleEndian(cipData, seqCount);
            mrBuf.AsSpan(0, mrLen).CopyTo(cipData.AsSpan(2));

            // The reply's connection_id must be the TO_conn_id (the ID PLC
            // assigned for us-to-PLC traffic) — not the OT_conn_id the PLC
            // put in the request (which identifies our endpoint). Use the
            // connection-id lookup; fall back to echoing if no lookup is
            // wired (loopback tests).
            uint replyConnId = msg.ConnectionId;
            if (ConnectionIdLookup != null)
            {
                uint ttoO = ConnectionIdLookup(msg.ConnectionId);
                if (ttoO != 0) replyConnId = ttoO;
            }

            var reply = new SendUnitDataMessage
            {
                SessionHandle = sessionHandle,
                Status = EncapsulationStatus.Success,
                SenderContext = msg.SenderContext,
                ConnectionId = replyConnId,
                CipData = cipData,
            };
            var outBuf = new byte[reply.WireSize];
            reply.WriteTo(outBuf);
            return outBuf;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(mrBuf);
        }
    }

    private byte[] HandleSendRRData(SendRRDataMessage msg, uint sessionHandle, IPEndPoint localEp, IPEndPoint remoteEp)
    {
        if (sessionHandle == 0 || !_sessions.IsValid(msg.SessionHandle))
            return BuildErrorResponse(EncapsulationCommand.SendRRData, msg.SessionHandle, msg.SenderContext, EncapsulationStatus.InvalidSessionHandle);

        // Parse MR request and dispatch
        if (!MrCodec.TryParseRequest(msg.CipData, out var serviceCode, out var path, out var data))
            return BuildErrorResponse(EncapsulationCommand.SendRRData, msg.SessionHandle, msg.SenderContext, EncapsulationStatus.IncorrectData);

        var cipResponse = _dispatch.Dispatch(serviceCode, path, data);

        // Encode MR response using pooled buffer
        var mrResponseBuf = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            int mrLen = cipResponse.Encode(mrResponseBuf);

            var replyItems = new List<CpfItem>(4)
            {
                new CpfItem { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
                new CpfItem { TypeId = CpfItemType.UnconnectedData, Data = mrResponseBuf.AsMemory(0, mrLen) },
            };

            // Successful Forward Open → let subclasses (IoEipAdapter) attach
            // Sockaddr Info items and fire their ConnectionOpened event.
            bool isForwardOpen = cipResponse.Status.IsSuccess &&
                                 (serviceCode == 0x54 || serviceCode == 0x5B);
            if (isForwardOpen)
            {
                OnForwardOpenReply(replyItems, serviceCode, data, cipResponse, localEp, remoteEp);
            }

            var replyCpfBuf = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                int replyCpfLen = CpfParser.Write(replyCpfBuf, replyItems.ToArray());

                // SendRRData payload = InterfaceHandle(4) + Timeout(2) + CPF items
                var responsePayload = new byte[6 + replyCpfLen];
                replyCpfBuf.AsSpan(0, replyCpfLen).CopyTo(responsePayload.AsSpan(6));

                return BuildResponse(EncapsulationCommand.SendRRData, sessionHandle, msg.SenderContext, responsePayload);
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

    /// <summary>
    /// Hook invoked on every successful Forward Open just before the reply CPF
    /// is built. The base implementation is a no-op; subclasses
    /// (<see cref="IoEipAdapter"/>) may append extra CPF items (e.g. Sockaddr
    /// Info) and fire callbacks.
    /// </summary>
    protected virtual void OnForwardOpenReply(List<CpfItem> cpfItems, byte serviceCode,
        ReadOnlyMemory<byte> requestData, CipServiceResponse response,
        IPEndPoint localEp, IPEndPoint remoteEp)
    {
    }

    /// <summary>Build a 16-byte sockaddr_in structure (big-endian for socket fields).
    /// Protected so the <see cref="IoEipAdapter"/> subclass can reuse it.</summary>
    protected static byte[] BuildSockaddrInfo(IPAddress address, int port)
    {
        var data = new byte[16];
        BinaryPrimitives.WriteInt16BigEndian(data, 2); // sin_family = AF_INET
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2), (ushort)port); // sin_port
        address.GetAddressBytes().CopyTo(data.AsSpan(4)); // sin_addr
        // sin_zero (8 bytes) already zeroed
        return data;
    }

    /// <summary>Build a success response with the given payload.</summary>
    private static byte[] BuildResponse(EncapsulationCommand command, uint sessionHandle, ulong senderContext, ReadOnlySpan<byte> payload)
    {
        var reply = new EncapsulationHeader
        {
            Command = command,
            Length = (ushort)payload.Length,
            SessionHandle = sessionHandle,
            SenderContext = senderContext,
        };
        var buf = new byte[EncapsulationHeader.Size + payload.Length];
        reply.WriteTo(buf);
        payload.CopyTo(buf.AsSpan(EncapsulationHeader.Size));
        return buf;
    }

    /// <summary>Build an error response with no payload.</summary>
    private static byte[] BuildErrorResponse(EncapsulationCommand command, uint sessionHandle, ulong senderContext, EncapsulationStatus status)
    {
        var reply = new EncapsulationHeader
        {
            Command = command,
            SessionHandle = sessionHandle,
            Status = status,
            SenderContext = senderContext,
        };
        var buf = new byte[EncapsulationHeader.Size];
        reply.WriteTo(buf);
        return buf;
    }

    /// <summary>Stop listening and release resources.</summary>
    public ValueTask DisposeAsync() => _socket.DisposeAsync();
}

/// <summary>
/// Simple growable byte buffer for accumulating partial TCP receives until
/// a full message is in hand. Append-and-drain semantics; not thread-safe
/// because each TCP connection has its own instance used only from its
/// dedicated read thread.
/// </summary>
internal sealed class TcpFrameAccumulator
{
    private byte[] _buf = new byte[4096];
    private int _len;

    public void Append(ReadOnlySpan<byte> data)
    {
        if (_len + data.Length > _buf.Length)
        {
            int newSize = _buf.Length;
            while (newSize < _len + data.Length) newSize *= 2;
            Array.Resize(ref _buf, newSize);
        }
        data.CopyTo(_buf.AsSpan(_len));
        _len += data.Length;
    }

    public ReadOnlySpan<byte> GetReadableBytes() => _buf.AsSpan(0, _len);

    public void Advance(int consumed)
    {
        if (consumed >= _len) { _len = 0; return; }
        Buffer.BlockCopy(_buf, consumed, _buf, 0, _len - consumed);
        _len -= consumed;
    }
}
