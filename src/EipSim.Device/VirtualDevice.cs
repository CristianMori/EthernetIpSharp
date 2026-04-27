using System.Buffers.Binary;
using System.Net;
using EipSim.Cip;
using EipSim.Connections;
using EipSim.Protocol;

namespace EipSim.Device;

public sealed class VirtualDevice : IAsyncDisposable
{
    public Guid Id { get; } = Guid.NewGuid();
    public string Name { get; }
    public IPAddress BoundAddress { get; }
    public IdentityInfo Identity { get; }
    public CipDispatcher Dispatcher { get; }
    public AssemblyObject Assemblies { get; }
    public ConnectionManagerObject ConnectionManager { get; }

    private EipAdapter? _adapter;
    private IEipUdpTransport? _udpTransport;

    // Injectable factories — null means use real implementations
    private readonly Func<IPEndPoint, IEipUdpTransport>? _udpFactory;
    private readonly Func<ICipDispatch, IdentityInfo, EipAdapter>? _adapterFactory;

    /// <summary>Convenience constructor using real implementations.</summary>
    public VirtualDevice(IdentityInfo identity, IPAddress bindAddress, string? name = null)
        : this(identity, bindAddress, new CipDispatcher(), new AssemblyObject(),
               new ConnectionManagerObject(), name) { }

    /// <summary>DI constructor — inject collaborators or mocks.</summary>
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
        ConnectionManager.ConnectionRemoved += OnConnectionRemoved;
    }

    public AssemblyInstance AddAssembly(uint instanceId, int dataSize, string? name = null) =>
        Assemblies.AddInstance(instanceId, dataSize, name);

    public int TcpPort { get; private set; } = EipAdapter.DefaultPort;
    public int UdpPort { get; private set; } = EipUdpTransport.IoPort;

    public Task StartAsync(CancellationToken ct = default) =>
        StartAsync(EipAdapter.DefaultPort, EipUdpTransport.IoPort, ct);

    public async Task StartAsync(int tcpPort, int udpPort, CancellationToken ct = default)
    {
        TcpPort = tcpPort;
        UdpPort = udpPort;

        _adapter = _adapterFactory != null
            ? _adapterFactory(Dispatcher, Identity)
            : new EipAdapter(Dispatcher, Identity);

        // When adapter detects a successful Forward Open, set RemoteEndpoint on the connection
        _adapter.ConnectionOpened += (cipResponseObj, plcEndpoint) =>
        {
            // Find the most recently created connection and set its remote endpoint
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
            if (conn != null && conn.State == Connections.ConnectionState.Established)
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

    private void OnConnectionRemoved(IoConnection conn) { }

    private int _toSendCount;

    private void ProduceIoData(IoConnection conn)
    {
        if (conn.State != ConnectionState.Established) return;
        if (_udpTransport == null || conn.RemoteEndpoint == null) return;
        Interlocked.Increment(ref _toSendCount);

        var assembly = Assemblies.GetAssembly(conn.ProducedAssemblyInstance);
        if (assembly == null) return;

        conn.EncapsulationSequenceNumber++;

        // T→O Class 1: [CIP seq count (2)] [assembly data] — no run/idle header from target
        byte[] ioData;
        if (conn.TransportClass == TransportClass.Class1)
        {
            conn.CipSequenceCount++;
            ioData = new byte[2 + assembly.DataSize];
            BinaryPrimitives.WriteUInt16LittleEndian(ioData, conn.CipSequenceCount);
            assembly.CopyDataTo(ioData.AsSpan(2));
        }
        else
        {
            ioData = new byte[assembly.DataSize];
            assembly.CopyDataTo(ioData);
        }

        try
        {
            _udpTransport.SendIoData(conn.RemoteEndpoint, conn.TtoOConnectionId,
                conn.EncapsulationSequenceNumber, ioData);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[UDP SEND ERROR] {ex.Message}");
        }
    }

    /// <summary>Number of T→O UDP packets sent (for diagnostics).</summary>
    public int TtoOSendCount => _toSendCount;

    private void CheckWatchdog(IoConnection conn)
    {
        if (conn.State != ConnectionState.Established) return;
        if (DateTime.UtcNow - conn.LastReceivedUtc > conn.ConnectionTimeout)
            ConnectionManager.TimeoutConnection(conn);
    }

    private void OnUdpDataReceived(uint connectionId, ReadOnlyMemory<byte> data)
    {
        var conn = ConnectionManager.FindByOtoTId(connectionId);
        if (conn == null || conn.State != ConnectionState.Established) return;

        conn.LastReceivedUtc = DateTime.UtcNow;

        // Class 1 data format: [CIP seq count (2)] [32-bit run/idle header (4)] [assembly data]
        ReadOnlyMemory<byte> ioData;
        if (conn.TransportClass == TransportClass.Class1 && data.Length >= 6)
            ioData = data.Slice(6); // Skip 2 seq + 4 run/idle header
        else
            ioData = data;

        Assemblies.GetAssembly(conn.ConsumedAssemblyInstance)?.SetData(ioData.Span);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var conn in ConnectionManager.ActiveConnections.ToList())
            ConnectionManager.RemoveConnection(conn);

        if (_udpTransport != null) await _udpTransport.DisposeAsync();
        if (_adapter != null) await _adapter.DisposeAsync();
    }
}
