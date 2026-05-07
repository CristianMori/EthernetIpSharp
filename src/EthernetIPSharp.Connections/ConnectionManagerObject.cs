using System.Buffers.Binary;
using System.Collections.Concurrent;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Connections;

/// <summary>
/// CIP Connection Manager Object (Class 0x06).
/// Handles Forward Open (0x54), Large Forward Open (0x5B), and Forward Close (0x4E).
/// Creates IoConnection instances and manages their lifecycle.
/// Registered as a CIP class in the dispatcher so explicit messages route to it.
/// </summary>
public sealed class ConnectionManagerObject
{
    /// <summary>CIP class code for Connection Manager.</summary>
    public const uint ClassCode = 0x06;

    /// <summary>Service code for Forward Open.</summary>
    public const byte ForwardOpenService = 0x54;

    /// <summary>Service code for Forward Close.</summary>
    public const byte ForwardCloseService = 0x4E;

    /// <summary>Service code for Large Forward Open.</summary>
    public const byte LargeForwardOpenService = 0x5B;

    /// <summary>Service code for Unconnected Send.</summary>
    public const byte UnconnectedSendService = 0x52;

    private readonly CipClass _cipClass;

    /// <summary>Active connections keyed by O→T connection ID (used for incoming UDP lookup).</summary>
    private readonly ConcurrentDictionary<uint, IoConnection> _connections = new();

    /// <summary>Counter for generating unique O→T connection IDs. Starts at 0 so first Increment returns 1.</summary>
    private uint _nextConnectionId;

    /// <summary>Fired when a new I/O connection is established via Forward Open.</summary>
    public event Action<IoConnection>? ConnectionEstablished;

    /// <summary>Fired when a connection is closed (Forward Close) or timed out.</summary>
    public event Action<IoConnection>? ConnectionRemoved;

    /// <summary>
    /// Delegate to validate that an assembly instance exists.
    /// Returns the assembly size in bytes, or -1 if the instance does not exist.
    /// Set by VirtualDevice to wire up assembly validation.
    /// </summary>
    public Func<uint, int>? ValidateAssembly { get; set; }

    /// <summary>
    /// Delegate to dispatch an inner CIP request (used by Unconnected Send).
    /// Set by VirtualDevice or LogixDispatcher to route the unwrapped request.
    /// </summary>
    public Func<byte, CipPath, ReadOnlyMemory<byte>, CipServiceResponse>? DispatchRequest { get; set; }

    /// <summary>The CIP class object for registration in the dispatcher.</summary>
    public CipClass CipClass => _cipClass;

    /// <summary>All currently active I/O connections.</summary>
    public ICollection<IoConnection> ActiveConnections => _connections.Values;

    /// <summary>
    /// Create the Connection Manager CIP class with standard attributes and services.
    /// Registers Forward Open (0x54), Large Forward Open (0x5B), and Forward Close (0x4E)
    /// as instance-level services on instance 1.
    /// </summary>
    public ConnectionManagerObject()
    {
        _cipClass = new CipClass(ClassCode, "Connection Manager", revision: 1);
        _cipClass.AddStandardInstanceServices();

        // Instance 1 with counter attributes (Vol1 §3-5.2)
        var inst = _cipClass.CreateInstance(1);
        for (ushort i = 1; i <= 8; i++)
            inst.AddAttribute(CipAttribute.Create(i, CipDataType.Uint, AttributeAccess.GetSingle | AttributeAccess.GetAll, (ushort)0));

        _cipClass.AddInstanceService(new CipServiceDefinition(ForwardOpenService, "Forward_Open", HandleForwardOpen));
        _cipClass.AddInstanceService(new CipServiceDefinition(ForwardCloseService, "Forward_Close", HandleForwardClose));
        _cipClass.AddInstanceService(new CipServiceDefinition(LargeForwardOpenService, "Large_Forward_Open", HandleLargeForwardOpen));
        _cipClass.AddInstanceService(new CipServiceDefinition(UnconnectedSendService, "Unconnected_Send", HandleUnconnectedSend));
    }

    /// <summary>Handle Forward Open (0x54) service request.</summary>
    private CipServiceResponse HandleForwardOpen(CipInstance instance, CipServiceRequest request)
    {
        return ProcessForwardOpen(request, isLarge: false);
    }

    /// <summary>Handle Large Forward Open (0x5B) service request.</summary>
    private CipServiceResponse HandleLargeForwardOpen(CipInstance instance, CipServiceRequest request)
    {
        return ProcessForwardOpen(request, isLarge: true);
    }

    /// <summary>
    /// Core Forward Open processing — shared by both 0x54 and 0x5B.
    /// Parses the request, validates assemblies, checks for duplicates,
    /// allocates connection IDs, creates the IoConnection, and builds the response.
    /// </summary>
    private CipServiceResponse ProcessForwardOpen(CipServiceRequest request, bool isLarge)
    {
        var fwdOpen = ForwardOpenRequest.Parse(request.Data.Span, isLarge);

        // Parse connection path to find assembly instances
        var pathResult = ConnectionPathParser.Parse(fwdOpen.ConnectionPath.Span, fwdOpen);

        // Validate assemblies exist
        if (ValidateAssembly != null)
        {
            if (pathResult.ConsumedAssemblyInstance.HasValue &&
                ValidateAssembly(pathResult.ConsumedAssemblyInstance.Value) < 0)
                return ForwardOpenError(request.ServiceCode, 0x0116); // Invalid connection point

            if (pathResult.ProducedAssemblyInstance.HasValue &&
                ValidateAssembly(pathResult.ProducedAssemblyInstance.Value) < 0)
                return ForwardOpenError(request.ServiceCode, 0x0116);
        }

        // Check for duplicate connection (matching triad)
        foreach (var existing in _connections.Values)
        {
            if (existing.ConnectionSerialNumber == fwdOpen.ConnectionSerialNumber &&
                existing.OriginatorVendorId == fwdOpen.OriginatorVendorId &&
                existing.OriginatorSerialNumber == fwdOpen.OriginatorSerialNumber)
            {
                return ForwardOpenError(request.ServiceCode, 0x0100); // Connection in use
            }
        }

        // Allocate connection IDs (Vol2 Table 3-3.2)
        // For P2P O→T: Target (us) chooses — scanner uses this ID when sending O→T UDP to us
        // For P2P T→O: Originator (scanner) chooses — we use their ID when sending T→O UDP back
        uint otoTId = Interlocked.Increment(ref _nextConnectionId);
        uint ttoOId = fwdOpen.TtoOConnectionId;

        var connection = new IoConnection
        {
            ConnectionSerialNumber = fwdOpen.ConnectionSerialNumber,
            OriginatorVendorId = fwdOpen.OriginatorVendorId,
            OriginatorSerialNumber = fwdOpen.OriginatorSerialNumber,
            OtoTConnectionId = otoTId,
            TtoOConnectionId = ttoOId,
            ConsumedAssemblyInstance = pathResult.ConsumedAssemblyInstance ?? 0,
            ProducedAssemblyInstance = pathResult.ProducedAssemblyInstance ?? 0,
            ConfigAssemblyInstance = pathResult.ConfigAssemblyInstance ?? 0,
            OtoTRpi = fwdOpen.OtoTRpi,
            TtoORpi = fwdOpen.TtoORpi,
            OtoTSize = fwdOpen.OtoTParams.ConnectionSize,
            TtoOSize = fwdOpen.TtoOParams.ConnectionSize,
            TransportClass = fwdOpen.TransportClass,
            TimeoutMultiplier = fwdOpen.ConnectionTimeoutMultiplier,
            State = ConnectionState.Established,
        };

        _connections[otoTId] = connection;

        ConnectionEstablished?.Invoke(connection);

        // Build Forward Open success response (Vol1 Table 3-5.19)
        var responseData = new byte[26];
        int off = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), otoTId); off += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), ttoOId); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(responseData.AsSpan(off), fwdOpen.ConnectionSerialNumber); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(responseData.AsSpan(off), fwdOpen.OriginatorVendorId); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), fwdOpen.OriginatorSerialNumber); off += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), fwdOpen.OtoTRpi); off += 4; // OT API
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), fwdOpen.TtoORpi); off += 4; // TO API
        responseData[off++] = 0; // Application Reply Size
        responseData[off++] = 0; // Reserved

        return CipServiceResponse.Success(request.ServiceCode, responseData.AsMemory(0, off));
    }

    /// <summary>
    /// Handle Forward Close (0x4E) — find connection by triad and remove it.
    /// </summary>
    private CipServiceResponse HandleForwardClose(CipInstance instance, CipServiceRequest request)
    {
        if (request.Data.Length < 10)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.NotEnoughData));

        var data = request.Data.Span;
        int offset = 2; // Skip priority/time_tick and timeout_ticks
        ushort connSerial = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
        ushort origVendor = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
        uint origSerial = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;

        // Find connection by triad
        IoConnection? found = null;
        foreach (var conn in _connections.Values)
        {
            if (conn.ConnectionSerialNumber == connSerial &&
                conn.OriginatorVendorId == origVendor &&
                conn.OriginatorSerialNumber == origSerial)
            {
                found = conn;
                break;
            }
        }

        if (found == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x01, 0x0107));

        RemoveConnection(found);

        // Build Forward Close success response
        var responseData = new byte[10];
        int off = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(responseData.AsSpan(off), connSerial); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(responseData.AsSpan(off), origVendor); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), origSerial); off += 4;
        responseData[off++] = 0; // Application Reply Size
        responseData[off++] = 0; // Reserved

        return CipServiceResponse.Success(request.ServiceCode, responseData.AsMemory(0, off));
    }

    /// <summary>Find a connection by its O→T connection ID (used for incoming UDP data lookup).</summary>
    public IoConnection? FindByOtoTId(uint connectionId) =>
        _connections.TryGetValue(connectionId, out var conn) ? conn : null;

    /// <summary>Remove a connection, dispose its timers, and fire ConnectionRemoved.</summary>
    public void RemoveConnection(IoConnection connection)
    {
        _connections.TryRemove(connection.OtoTConnectionId, out _);
        connection.Dispose();
        ConnectionRemoved?.Invoke(connection);
    }

    /// <summary>Mark a connection as timed out and remove it.</summary>
    public void TimeoutConnection(IoConnection connection)
    {
        connection.State = ConnectionState.TimedOut;
        RemoveConnection(connection);
    }

    /// <summary>
    /// Handle Unconnected Send (0x52) — unwrap the embedded CIP request and dispatch it.
    /// Format: priority(1) + timeout(1) + msg_length(UINT) + embedded_MR_request + [pad] + route_path_size(1) + reserved(1) + route_path
    /// </summary>
    private CipServiceResponse HandleUnconnectedSend(CipInstance instance, CipServiceRequest request)
    {
        if (DispatchRequest == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.ServiceNotSupported));

        if (request.Data.Length < 4)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.NotEnoughData));

        var span = request.Data.Span;
        // Skip priority/time_tick (1) + timeout_ticks (1)
        int offset = 2;
        ushort msgLength = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset)); offset += 2;

        if (offset + msgLength > request.Data.Length)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.NotEnoughData));

        // Extract the embedded MR request
        var embeddedRequest = request.Data.Slice(offset, msgLength);

        // Parse the embedded MR request
        if (!MrCodec.TryParseRequest(embeddedRequest, out var serviceCode, out var path, out var data))
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.PathSegmentError));

        // Dispatch the inner request through the full CIP dispatch chain
        return DispatchRequest(serviceCode, path, data);
    }

    /// <summary>Build a Forward Open error response with general status 0x01 and the given extended status.</summary>
    private static CipServiceResponse ForwardOpenError(byte serviceCode, ushort extendedStatus)
    {
        return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x01, extendedStatus));
    }
}
