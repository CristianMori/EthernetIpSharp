using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using EipSim.Cip;

namespace EipSim.Connections;

/// <summary>
/// CIP Connection Manager Object (Class 0x06).
/// Handles Forward Open (0x54), Large Forward Open (0x5B), and Forward Close (0x4E).
/// </summary>
public sealed class ConnectionManagerObject
{
    public const uint ClassCode = 0x06;
    public const byte ForwardOpenService = 0x54;
    public const byte ForwardCloseService = 0x4E;
    public const byte LargeForwardOpenService = 0x5B;

    private readonly CipClass _cipClass;
    private readonly ConcurrentDictionary<uint, IoConnection> _connectionsByOtoTId = new();
    private readonly ConcurrentDictionary<uint, IoConnection> _connectionsByTtoOId = new();
    private uint _nextConnectionId = 1;

    /// <summary>Called when a new I/O connection is established.</summary>
    public event Action<IoConnection>? ConnectionEstablished;
    /// <summary>Called when a connection is closed or timed out.</summary>
    public event Action<IoConnection>? ConnectionRemoved;

    /// <summary>
    /// Delegate to validate that an assembly instance exists and return its size.
    /// Returns -1 if the instance does not exist.
    /// </summary>
    public Func<uint, int>? ValidateAssembly { get; set; }

    public CipClass CipClass => _cipClass;
    public ICollection<IoConnection> ActiveConnections => _connectionsByOtoTId.Values;

    public ConnectionManagerObject()
    {
        _cipClass = new CipClass(ClassCode, "Connection Manager", revision: 1);
        _cipClass.AddStandardInstanceServices();

        var inst = _cipClass.CreateInstance(1);
        // Instance attributes (counters) — all start at 0
        for (ushort i = 1; i <= 8; i++)
            inst.AddAttribute(CipAttribute.Create(i, CipDataType.Uint, AttributeAccess.GetSingle | AttributeAccess.GetAll, (ushort)0));

        // Register Forward Open/Close as unconnected services (handled via UCMM at instance 1)
        _cipClass.AddInstanceService(new CipServiceDefinition(ForwardOpenService, "Forward_Open", HandleForwardOpen));
        _cipClass.AddInstanceService(new CipServiceDefinition(ForwardCloseService, "Forward_Close", HandleForwardClose));
        _cipClass.AddInstanceService(new CipServiceDefinition(LargeForwardOpenService, "Large_Forward_Open", HandleLargeForwardOpen));
    }

    private CipServiceResponse HandleForwardOpen(CipInstance instance, CipServiceRequest request)
    {
        return ProcessForwardOpen(instance, request, isLarge: false);
    }

    private CipServiceResponse HandleLargeForwardOpen(CipInstance instance, CipServiceRequest request)
    {
        return ProcessForwardOpen(instance, request, isLarge: true);
    }

    private CipServiceResponse ProcessForwardOpen(CipInstance instance, CipServiceRequest request, bool isLarge)
    {
        if (request.Data.Length < 30)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.NotEnoughData));

        var fwdOpen = ForwardOpenRequest.Parse(request.Data.Span, isLarge);

        // Parse connection path to find assembly instances
        var pathResult = ConnectionPathParser.Parse(fwdOpen.ConnectionPath.Span, fwdOpen);

        // Validate assemblies exist
        if (ValidateAssembly != null)
        {
            if (pathResult.ConsumedAssemblyInstance.HasValue)
            {
                int size = ValidateAssembly(pathResult.ConsumedAssemblyInstance.Value);
                if (size < 0)
                    return ForwardOpenError(request.ServiceCode, 0x0116); // Invalid connection point
            }
            if (pathResult.ProducedAssemblyInstance.HasValue)
            {
                int size = ValidateAssembly(pathResult.ProducedAssemblyInstance.Value);
                if (size < 0)
                    return ForwardOpenError(request.ServiceCode, 0x0116);
            }
        }

        // Check for duplicate connection (matching triad)
        foreach (var existing in _connectionsByOtoTId.Values)
        {
            if (existing.ConnectionSerialNumber == fwdOpen.ConnectionSerialNumber &&
                existing.OriginatorVendorId == fwdOpen.OriginatorVendorId &&
                existing.OriginatorSerialNumber == fwdOpen.OriginatorSerialNumber)
            {
                return ForwardOpenError(request.ServiceCode, 0x0100); // Connection in use
            }
        }

        // Allocate connection IDs (Vol2 Table 3-3.2)
        // For P2P O→T: Target (us) chooses — PLC will use this ID when sending O→T UDP to us
        // For P2P T→O: Originator (PLC) chooses — we must use PLC's ID when sending T→O UDP back
        uint otoTId = Interlocked.Increment(ref _nextConnectionId);  // We assign
        uint ttoOId = fwdOpen.TtoOConnectionId;                      // PLC assigned

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

        _connectionsByOtoTId[otoTId] = connection;
        _connectionsByTtoOId[ttoOId] = connection;

        ConnectionEstablished?.Invoke(connection);

        // Build Forward Open success response (Vol1 Table 3-5.19)
        var responseData = new byte[26];
        int off = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), otoTId); off += 4;  // OT Connection ID
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), ttoOId); off += 4;  // TO Connection ID
        BinaryPrimitives.WriteUInt16LittleEndian(responseData.AsSpan(off), fwdOpen.ConnectionSerialNumber); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(responseData.AsSpan(off), fwdOpen.OriginatorVendorId); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), fwdOpen.OriginatorSerialNumber); off += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), fwdOpen.OtoTRpi); off += 4;  // OT API
        BinaryPrimitives.WriteUInt32LittleEndian(responseData.AsSpan(off), fwdOpen.TtoORpi); off += 4;  // TO API
        responseData[off++] = 0; // Application Reply Size
        responseData[off++] = 0; // Reserved

        return CipServiceResponse.Success(request.ServiceCode, responseData.AsMemory(0, off));
    }

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
        foreach (var conn in _connectionsByOtoTId.Values)
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
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x01, 0x0107)); // Connection not found

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

    /// <summary>Find a connection by its O→T connection ID (used for incoming UDP data).</summary>
    public IoConnection? FindByOtoTId(uint connectionId) =>
        _connectionsByOtoTId.TryGetValue(connectionId, out var conn) ? conn : null;

    /// <summary>Remove a connection and fire the event.</summary>
    public void RemoveConnection(IoConnection connection)
    {
        _connectionsByOtoTId.TryRemove(connection.OtoTConnectionId, out _);
        _connectionsByTtoOId.TryRemove(connection.TtoOConnectionId, out _);
        connection.Dispose();
        ConnectionRemoved?.Invoke(connection);
    }

    /// <summary>Handle connection timeout.</summary>
    public void TimeoutConnection(IoConnection connection)
    {
        connection.State = ConnectionState.TimedOut;
        RemoveConnection(connection);
    }

    private static CipServiceResponse ForwardOpenError(byte serviceCode, ushort extendedStatus)
    {
        return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x01, extendedStatus));
    }
}
