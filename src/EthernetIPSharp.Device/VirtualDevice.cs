using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;
using EthernetIPSharp.Protocol;
using EthernetIPSharp.Protocol.Messages;

namespace EthernetIPSharp.Device;

/// <summary>
/// Abstract base for an EtherNet/IP device.
/// Owns CIP dispatcher, assembly I/O, connection manager, TCP adapter, and UDP transport.
/// Subclasses override virtual methods to handle safety vs standard I/O framing.
/// </summary>
public abstract class VirtualDevice : IAsyncDisposable
{
    public Guid Id { get; } = Guid.NewGuid();
    public string Name { get; }
    public IPAddress BoundAddress { get; }
    public IdentityInfo Identity { get; }
    public CipDispatcher Dispatcher { get; }
    public AssemblyObject Assemblies { get; }
    public ConnectionManagerObject ConnectionManager { get; }
    public int TtoOSendCount => _toSendCount;
    public int TcpPort { get; private set; } = EipAdapter.DefaultPort;
    public int UdpPort { get; private set; } = EipUdpTransport.IoPort;

    private IoEipAdapter? _adapter;
    private IEipUdpTransport? _udpTransport;
    private int _toSendCount;

    private readonly Func<IPEndPoint, IEipUdpTransport>? _udpFactory;
    private readonly Func<ICipDispatch, IdentityInfo, IoEipAdapter>? _adapterFactory;

    /// <summary>Convenience constructor using real implementations.</summary>
    protected VirtualDevice(IdentityInfo identity, IPAddress bindAddress, string? name = null)
        : this(identity, bindAddress, new CipDispatcher(), new AssemblyObject(),
               new ConnectionManagerObject(), name) { }

    /// <summary>DI constructor — inject collaborators or mocks.</summary>
    protected VirtualDevice(
        IdentityInfo identity,
        IPAddress bindAddress,
        CipDispatcher dispatcher,
        AssemblyObject assemblies,
        ConnectionManagerObject connectionManager,
        string? name = null,
        Func<IPEndPoint, IEipUdpTransport>? udpFactory = null,
        Func<ICipDispatch, IdentityInfo, IoEipAdapter>? adapterFactory = null)
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

        ConnectionManager.DispatchRequest = (svc, path, data) => Dispatcher.Dispatch(svc, path, data);

        Dispatcher.RegisterClass(IdentityObject.Create(identity));
        Dispatcher.RegisterClass(TcpIpInterfaceObject.Create(bindAddress));
        Dispatcher.RegisterClass(EthernetLinkObject.Create(bindAddress));
        Dispatcher.RegisterClass(Assemblies.CipClass);
        Dispatcher.RegisterClass(ConnectionManager.CipClass);

        ConnectionManager.ConnectionEstablished += OnConnectionEstablishedInternal;
    }

    public AssemblyInstance AddAssembly(uint instanceId, int dataSize, string? name = null) =>
        Assemblies.AddInstance(instanceId, dataSize, name);

    public Task StartAsync(CancellationToken ct = default) =>
        StartAsync(EipAdapter.DefaultPort, EipUdpTransport.IoPort, ct);

    public async Task StartAsync(int tcpPort, int udpPort, CancellationToken ct = default)
    {
        TcpPort = tcpPort;
        UdpPort = udpPort;

        // Boost process priority to reduce preemption when other apps grab focus.
        // High is aggressive but safe; RealTime would risk starving the system.
        try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High; }
        catch { /* may fail on restricted accounts; non-fatal */ }

        _adapter = _adapterFactory != null
            ? _adapterFactory(Dispatcher, Identity)
            : new IoEipAdapter(Dispatcher, Identity);

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
        // Decoupling is provided by UdpSocket (RX thread → queue → dispatch thread).
        // Our handler runs on the dispatch thread and can block (e.g. for TCOO
        // sends) without affecting socket receive. We get typed IMessages
        // from the transport's CPF parser.
        _udpTransport.MessageReceived += OnUdpMessageReceived;

        await _udpTransport.StartAsync(ct);
    }

    // ==================== Virtual Methods ====================

    /// <summary>Called when a connection is ready to start production. Override to delay safety production.</summary>
    protected virtual void OnConnectionReady(IoConnection conn)
    {
        if (conn.ProducedAssemblyInstance != 0 && conn.TtoORpi > 0)
            StartProductionThread(conn);
    }

    /// <summary>Produce T→O data for one cycle. Override for safety framing.</summary>
    protected virtual void ProduceIoData(IoConnection conn)
    {
        if (conn.State != ConnectionState.Established) return;
        if (_udpTransport == null || conn.RemoteEndpoint == null) return;

        var assembly = Assemblies.GetAssembly(conn.ProducedAssemblyInstance);
        if (assembly == null) return;

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

            SendUdpIoData(conn, ioData.AsSpan(0, ioSize));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ioData);
        }
    }

    /// <summary>Handle incoming O→T data after connection lookup. Override for safety decoding.</summary>
    protected virtual void HandleReceivedIoData(IoConnection conn, ReadOnlyMemory<byte> data)
    {
        ReadOnlyMemory<byte> ioData;
        if (conn.TransportClass == TransportClass.Class1 && data.Length >= 6)
            ioData = data.Slice(6);
        else
            ioData = data;

        Assemblies.GetAssembly(conn.ConsumedAssemblyInstance)?.SetData(ioData.Span);
    }

    /// <summary>Called when a connection's remote endpoint is updated from UDP sender. Override for safety partner propagation.</summary>
    protected virtual void OnRemoteEndpointUpdated(IoConnection conn, IPEndPoint senderEp) { }

    // ==================== Protected Helpers ====================

    /// <summary>Send raw UDP I/O data on a connection's T→O path.</summary>
    protected void SendUdpIoData(IoConnection conn, ReadOnlySpan<byte> data)
    {
        if (_udpTransport == null || conn.RemoteEndpoint == null) return;
        Interlocked.Increment(ref _toSendCount);
        _udpTransport.SendIoData(conn.RemoteEndpoint, conn.TtoOConnectionId,
            conn.EncapsulationSequenceNumber, data);
        conn.EncapsulationSequenceNumber++;
    }

    // Counter for round-robin core assignment of production threads. Each new
    // production thread gets pinned to its own CPU core (skipping core 0, which
    // the OS prefers for interrupts and the receive loop).
    private static int _nextProductionCore = 1;

    /// <summary>Start a high-res production thread for a connection.</summary>
    protected void StartProductionThread(IoConnection conn)
    {
        if (conn.ProductionThread != null) return;

        var cts = new CancellationTokenSource();
        conn.ProductionCts = cts;
        long rpiTicks = conn.TtoORpi * Stopwatch.Frequency / 1_000_000;
        int coreIndex = Interlocked.Increment(ref _nextProductionCore) % Math.Max(1, Environment.ProcessorCount);

        var thread = new Thread(() =>
        {
            // Pin this OS thread to a single core. Avoids cross-core migration
            // latency and helps keep Stopwatch (RDTSC) monotonic across reads.
            PinCurrentThreadToCore(coreIndex);

            // Fire at EXACT RPI cadence using a Windows high-resolution
            // waitable timer (~500µs accuracy, no busy-wait, no global timer
            // resolution change). Real CIP devices send at exactly the
            // negotiated RPI; PLC's safety task behaves better with that
            // timing. nextSend advances by rpiTicks from itself (not from
            // "now") so the cadence is self-correcting.
            IntPtr hTimer = IntPtr.Zero;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                hTimer = CreateWaitableTimerExW(IntPtr.Zero, null,
                    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);

            // Opt-in per-iteration latency CSV — set ETHERNETIPSHARP_LAG_CSV=1
            // to enable. Logs every fire so we can see trend and periodicity
            // in post-processing. BufferedStream amortizes disk I/O; 8KB buffer
            // ≈ 200+ records per flush so the hot path almost never blocks.
            // One file per producer connection in %TEMP%\lag_conn_*.csv.
            bool lagEnabled = Environment.GetEnvironmentVariable("ETHERNETIPSHARP_LAG_CSV") == "1";
            BufferedStream? lagStream = null;
            StreamWriter? lagWriter = null;
            if (lagEnabled)
            {
                string lagPath = Path.Combine(Path.GetTempPath(),
                    $"lag_conn_{conn.TtoOConnectionId:X8}_{DateTime.Now:yyyyMMddTHHmmss}.csv");
                lagStream = new BufferedStream(
                    new FileStream(lagPath, FileMode.Create, FileAccess.Write, FileShare.Read), 8192);
                lagWriter = new StreamWriter(lagStream);
                lagWriter.WriteLine("iter_us,wake_overshoot_us,produce_us,total_us");
            }
            long lagT0 = Stopwatch.GetTimestamp();
            double tickToUs = 1_000_000.0 / Stopwatch.Frequency;

            try
            {
                long nextSend = Stopwatch.GetTimestamp() + rpiTicks;
                while (!cts.Token.IsCancellationRequested)
                {
                    long remaining = nextSend - Stopwatch.GetTimestamp();
                    if (remaining > 0)
                    {
                        if (hTimer != IntPtr.Zero)
                        {
                            // Negative dueTime = relative, in 100ns units.
                            long delay100ns = -(remaining * 10_000_000 / Stopwatch.Frequency);
                            if (SetWaitableTimer(hTimer, ref delay100ns, 0,
                                    IntPtr.Zero, IntPtr.Zero, false))
                            {
                                WaitForSingleObject(hTimer, 100);
                            }
                        }
                        else
                        {
                            // Fallback: yield until time elapsed (older Windows / non-Windows).
                            while (Stopwatch.GetTimestamp() < nextSend
                                   && !cts.Token.IsCancellationRequested)
                                Thread.Sleep(0);
                        }
                        continue;
                    }

                    // Latency instrumentation — three checkpoints around the produce.
                    long t_wake   = Stopwatch.GetTimestamp();      // we passed the wait
                    try { ProduceIoData(conn); }
                    catch (Exception ex) { Console.WriteLine($"[PROD-ERROR] {ex.GetType().Name}: {ex.Message}"); }
                    long t_after  = Stopwatch.GetTimestamp();      // produce done

                    if (lagWriter != null)
                    {
                        long iter_us      = (long)((t_wake - lagT0) * tickToUs);
                        long overshoot_us = (long)((t_wake - nextSend) * tickToUs);
                        long produce_us   = (long)((t_after - t_wake) * tickToUs);
                        long total_us     = (long)((t_after - nextSend) * tickToUs);
                        lagWriter.Write(iter_us); lagWriter.Write(',');
                        lagWriter.Write(overshoot_us); lagWriter.Write(',');
                        lagWriter.Write(produce_us); lagWriter.Write(',');
                        lagWriter.WriteLine(total_us);
                    }

                    nextSend += rpiTicks;
                    // If we fall behind by more than one RPI, re-anchor to now
                    // instead of bursting catch-up frames.
                    long now = Stopwatch.GetTimestamp();
                    if (now - nextSend > rpiTicks)
                        nextSend = now + rpiTicks;
                }
            }
            finally
            {
                if (hTimer != IntPtr.Zero) CloseHandle(hTimer);
                lagWriter?.Dispose();
                lagStream?.Dispose();
            }
        })
        {
            IsBackground = true,
            Priority = ThreadPriority.Highest,
            Name = $"Produce-Asm{conn.ProducedAssemblyInstance}"
        };
        conn.ProductionThread = thread;
        thread.Start();
    }

    // ==================== Windows P/Invoke ====================

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr SetThreadAffinityMask(IntPtr hThread, IntPtr dwThreadAffinityMask);

    // High-resolution waitable timer (Win10 1803+) — ~500µs accuracy.
    private const uint CREATE_WAITABLE_TIMER_HIGH_RESOLUTION = 0x00000002;
    private const uint TIMER_ALL_ACCESS = 0x1F0003;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWaitableTimerExW(IntPtr lpTimerAttributes,
        string? lpTimerName, uint dwFlags, uint dwDesiredAccess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetWaitableTimer(IntPtr hTimer, ref long lpDueTime,
        int lPeriod, IntPtr pfnCompletionRoutine, IntPtr lpArgToCompletionRoutine,
        bool fResume);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static void PinCurrentThreadToCore(int coreIndex)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        try
        {
            // Disallow CLR from moving this managed thread between OS threads.
            Thread.BeginThreadAffinity();
            SetThreadAffinityMask(GetCurrentThread(), (IntPtr)(1L << coreIndex));
        }
        catch { /* non-fatal — pinning is best effort */ }
    }

    // ==================== Private ====================

    private void OnConnectionEstablishedInternal(IoConnection conn)
    {
        // Apply the Forward Open Connection Data (Simple Data Segment, 0x80)
        // into the matching config assembly so the originator's config bytes
        // are visible to the device.
        if (!conn.ConfigData.IsEmpty && conn.ConfigAssemblyInstance != 0)
        {
            var asm = Assemblies.GetAssembly(conn.ConfigAssemblyInstance);
            asm?.SetData(conn.ConfigData.Span);
        }

        if (conn.OtoTRpi > 0)
        {
            var timeout = conn.ConnectionTimeout;
            conn.WatchdogTimer = new Timer(_ => CheckWatchdog(conn), null, timeout, timeout);
        }

        OnConnectionReady(conn);
    }

    /// <summary>Handle a typed UDP message. Runs on UdpSocket's dispatch thread —
    /// safe to do synchronous work (CRC check, TCOO send, etc).</summary>
    private void OnUdpMessageReceived(IMessage message)
    {
        // Today we only care about connected I/O data. Other message kinds
        // (e.g. ListIdentity, multicast addressing) would be dispatched here too.
        if (message is not CpfConnectedDataMessage cpf) return;

        var conn = ConnectionManager.FindByOtoTId(cpf.ConnectionId);
        if (conn == null || conn.State != ConnectionState.Established) return;

        // Learn / update the scanner's UDP sender endpoint.
        if (conn.RemoteEndpoint == null || conn.RemoteEndpoint.Port != cpf.RemoteEndpoint.Port)
        {
            conn.RemoteEndpoint = cpf.RemoteEndpoint;
            OnRemoteEndpointUpdated(conn, cpf.RemoteEndpoint);
        }

        conn.LastReceivedUtc = DateTime.UtcNow;
        conn.FirstReceived = true;
        HandleReceivedIoData(conn, cpf.Payload);
    }

    private void CheckWatchdog(IoConnection conn)
    {
        if (conn.State != ConnectionState.Established) return;
        // CIP Vol 1 §3-4.5.2: don't count until the first inbound frame.
        if (!conn.FirstReceived) return;
        if (DateTime.UtcNow - conn.LastReceivedUtc > conn.ConnectionTimeout)
            ConnectionManager.TimeoutConnection(conn);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var conn in ConnectionManager.ActiveConnections.ToList())
            ConnectionManager.RemoveConnection(conn);

        if (_udpTransport != null) await _udpTransport.DisposeAsync();
        if (_adapter != null) await _adapter.DisposeAsync();
    }
}
