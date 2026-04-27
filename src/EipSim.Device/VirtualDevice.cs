using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using EipSim.Cip;
using EipSim.Connections;
using EipSim.Protocol;

namespace EipSim.Device;

/// <summary>
/// A fully composed simulated EtherNet/IP device.
/// Owns a CIP dispatcher, assembly I/O buffers, connection manager, TCP adapter, and UDP transport.
/// Registers standard CIP objects (Identity, TCP/IP Interface, Ethernet Link, Assembly, Connection Manager).
/// Manages I/O connection lifecycle: production timers, watchdog timers, and data routing.
/// </summary>
public sealed class VirtualDevice : IAsyncDisposable
{
    /// <summary>Unique identifier for this virtual device instance.</summary>
    public Guid Id { get; } = Guid.NewGuid();

    /// <summary>Human-readable device name.</summary>
    public string Name { get; }

    /// <summary>IP address this device is bound to.</summary>
    public IPAddress BoundAddress { get; }

    /// <summary>Device identity information (vendor, product, serial, etc.).</summary>
    public IdentityInfo Identity { get; }

    /// <summary>CIP dispatcher that routes explicit messages to registered CIP objects.</summary>
    public CipDispatcher Dispatcher { get; }

    /// <summary>Assembly object managing I/O data buffers.</summary>
    public AssemblyObject Assemblies { get; }

    /// <summary>Connection manager handling Forward Open/Close lifecycle.</summary>
    public ConnectionManagerObject ConnectionManager { get; }

    /// <summary>Number of T→O UDP packets sent (for diagnostics).</summary>
    public int TtoOSendCount => _toSendCount;

    /// <summary>The TCP port this device is listening on.</summary>
    public int TcpPort { get; private set; } = EipAdapter.DefaultPort;

    /// <summary>The UDP port for I/O data.</summary>
    public int UdpPort { get; private set; } = EipUdpTransport.IoPort;

    private EipAdapter? _adapter;
    private IEipUdpTransport? _udpTransport;
    private int _toSendCount;

    // Injectable factories — null means use real implementations
    private readonly Func<IPEndPoint, IEipUdpTransport>? _udpFactory;
    private readonly Func<ICipDispatch, IdentityInfo, EipAdapter>? _adapterFactory;

    /// <summary>Convenience constructor using real implementations.</summary>
    public VirtualDevice(IdentityInfo identity, IPAddress bindAddress, string? name = null)
        : this(identity, bindAddress, new CipDispatcher(), new AssemblyObject(),
               new ConnectionManagerObject(), name) { }

    /// <summary>
    /// DI constructor — inject collaborators or mocks.
    /// Registers standard CIP objects and wires up connection lifecycle events.
    /// </summary>
    public VirtualDevice(
        IdentityInfo identity,
        IPAddress bindAddress,
        CipDispatcher dispatcher,
        AssemblyObject assemblies,
        ConnectionManagerObject connectionManager,
        string? name = null,
        Func<IPEndPoint, IEipUdpTransport>? udpFactory = null,
        Func<ICipDispatch, IdentityInfo, EipAdapter>? adapterFactory = null)
    {
        Identity = identity;
        BoundAddress = bindAddress;
        Name = name ?? identity.ProductName;
        Dispatcher = dispatcher;
        Assemblies = assemblies;
        ConnectionManager = connectionManager;
        _udpFactory = udpFactory;
        _adapterFactory = adapterFactory;

        ConnectionManager.ValidateAssembly = instanceId =>
        {
            var asm = Assemblies.GetAssembly(instanceId);
            return asm?.DataSize ?? -1;
        };

        Dispatcher.RegisterClass(IdentityObject.Create(identity));
        Dispatcher.RegisterClass(TcpIpInterfaceObject.Create(bindAddress));
        Dispatcher.RegisterClass(EthernetLinkObject.Create());
        Dispatcher.RegisterClass(Assemblies.CipClass);
        Dispatcher.RegisterClass(ConnectionManager.CipClass);

        ConnectionManager.ConnectionEstablished += OnConnectionEstablished;
    }

    /// <summary>Add an assembly instance. Call before StartAsync.</summary>
    public AssemblyInstance AddAssembly(uint instanceId, int dataSize, string? name = null) =>
        Assemblies.AddInstance(instanceId, dataSize, name);

    /// <summary>Start listening on the default EtherNet/IP ports (TCP 44818, UDP 2222).</summary>
    public Task StartAsync(CancellationToken ct = default) =>
        StartAsync(EipAdapter.DefaultPort, EipUdpTransport.IoPort, ct);

    /// <summary>Start listening on the specified TCP and UDP ports.</summary>
    public async Task StartAsync(int tcpPort, int udpPort, CancellationToken ct = default)
    {
        TcpPort = tcpPort;
        UdpPort = udpPort;

        _adapter = _adapterFactory != null
            ? _adapterFactory(Dispatcher, Identity)
            : new EipAdapter(Dispatcher, Identity);

        // When adapter detects a successful Forward Open, set RemoteEndpoint on the new connection
        _adapter.ConnectionOpened += (_, plcEndpoint) =>
        {
            foreach (var conn in ConnectionManager.ActiveConnections)
            {
                if (conn.RemoteEndpoint == null)
                {
                    conn.RemoteEndpoint = plcEndpoint;
                    break;
                }
            }
        };

        _adapter.UdpPort = udpPort;
        await _adapter.ListenAsync(BoundAddress, tcpPort, ct);

        var udpEndpoint = new IPEndPoint(BoundAddress, udpPort);
        _udpTransport = _udpFactory != null
            ? _udpFactory(udpEndpoint)
            : new EipUdpTransport(udpEndpoint);
        _udpTransport.DataReceived += OnUdpDataReceived;

        // Update connection RemoteEndpoint from actual UDP sender (handles ephemeral ports)
        _udpTransport.DataReceivedWithSender += (connId, senderEp) =>
        {
            var conn = ConnectionManager.FindByOtoTId(connId);
            if (conn != null && conn.State == ConnectionState.Established)
            {
                if (conn.RemoteEndpoint == null ||
                    conn.RemoteEndpoint.Port != senderEp.Port)
                {
                    conn.RemoteEndpoint = senderEp;
                }
            }
        };

        await _udpTransport.StartAsync(ct);
    }

    /// <summary>Start production and watchdog timers when a new I/O connection is established.</summary>
    private void OnConnectionEstablished(IoConnection conn)
    {
        if (conn.ProducedAssemblyInstance != 0 && conn.TtoORpi > 0)
        {
            var interval = TimeSpan.FromMicroseconds(conn.TtoORpi);
            if (interval < TimeSpan.FromMilliseconds(1))
                interval = TimeSpan.FromMilliseconds(1);
            conn.ProductionTimer = new Timer(_ => ProduceIoData(conn), null, interval, interval);
        }

        if (conn.OtoTRpi > 0)
        {
            var timeout = conn.ConnectionTimeout;
            conn.WatchdogTimer = new Timer(_ => CheckWatchdog(conn), null, timeout, timeout);
        }
    }

    /// <summary>
    /// Produce T→O I/O data on the timer tick.
    /// Class 1: prepends 2-byte CIP sequence count (no run/idle header from target).
    /// Uses ArrayPool to avoid per-tick heap allocation.
    /// </summary>
    private void ProduceIoData(IoConnection conn)
    {
        if (conn.State != ConnectionState.Established) return;
        if (_udpTransport == null || conn.RemoteEndpoint == null) return;

        var assembly = Assemblies.GetAssembly(conn.ProducedAssemblyInstance);
        if (assembly == null) return;

        Interlocked.Increment(ref _toSendCount);
        conn.EncapsulationSequenceNumber++;

        // T→O Class 1: [CIP seq count (2)] [assembly data] — no run/idle header from target
        int ioSize = conn.TransportClass == TransportClass.Class1
            ? 2 + assembly.DataSize
            : assembly.DataSize;

        var ioData = ArrayPool<byte>.Shared.Rent(ioSize);
        try
        {
            if (conn.TransportClass == TransportClass.Class1)
            {
                conn.CipSequenceCount++;
                BinaryPrimitives.WriteUInt16LittleEndian(ioData, conn.CipSequenceCount);
                assembly.CopyDataTo(ioData.AsSpan(2));
            }
            else
            {
                assembly.CopyDataTo(ioData);
            }

            _udpTransport.SendIoData(conn.RemoteEndpoint, conn.TtoOConnectionId,
                conn.EncapsulationSequenceNumber, ioData.AsSpan(0, ioSize));
        }
        catch { } // Timer thread — swallow send errors
        finally
        {
            ArrayPool<byte>.Shared.Return(ioData);
        }
    }

    /// <summary>Check if the connection has timed out due to missing O→T packets.</summary>
    private void CheckWatchdog(IoConnection conn)
    {
        if (conn.State != ConnectionState.Established) return;
        if (DateTime.UtcNow - conn.LastReceivedUtc > conn.ConnectionTimeout)
            ConnectionManager.TimeoutConnection(conn);
    }

    /// <summary>
    /// Handle incoming O→T UDP data.
    /// Class 1 from originator: strips 2-byte CIP seq count + 4-byte run/idle header.
    /// Writes remaining data into the consumed assembly buffer.
    /// </summary>
    private void OnUdpDataReceived(uint connectionId, ReadOnlyMemory<byte> data)
    {
        var conn = ConnectionManager.FindByOtoTId(connectionId);
        if (conn == null || conn.State != ConnectionState.Established) return;

        conn.LastReceivedUtc = DateTime.UtcNow;

        // O→T Class 1 from originator: [CIP seq count (2)] [run/idle header (4)] [assembly data]
        ReadOnlyMemory<byte> ioData;
        if (conn.TransportClass == TransportClass.Class1 && data.Length >= 6)
            ioData = data.Slice(6); // Skip 2 seq + 4 run/idle header
        else
            ioData = data;

        Assemblies.GetAssembly(conn.ConsumedAssemblyInstance)?.SetData(ioData.Span);
    }

    /// <summary>Dispose all connections, UDP transport, and TCP adapter.</summary>
    public async ValueTask DisposeAsync()
    {
        foreach (var conn in ConnectionManager.ActiveConnections.ToList())
            ConnectionManager.RemoveConnection(conn);

        if (_udpTransport != null) await _udpTransport.DisposeAsync();
        if (_adapter != null) await _adapter.DisposeAsync();
    }
}
