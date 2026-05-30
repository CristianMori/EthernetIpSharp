using System.Buffers.Binary;
using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Protocol.Messages;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// An active I/O connection from the scanner (originator) side.
/// Produces O→T data at the configured RPI, consumes T→O data from the target.
/// </summary>
public sealed class ScannerConnection : IAsyncDisposable
{
    private readonly EipScanner _scanner;
    private readonly EipUdpTransport _udp;
    private readonly byte[] _consumedData; // O→T: what we send to target
    private readonly byte[] _producedData; // T→O: what we receive from target
    private Timer? _productionTimer;
    private uint _encapSeqNum;
    private ushort _cipSeqCount;

    internal uint OtoTConnectionId { get; }
    internal uint TtoOConnectionId { get; }
    internal ushort ConnectionSerial { get; }
    internal ushort OriginatorVendor { get; }
    internal uint OriginatorSerial { get; }

    public ForwardOpenConfig Config { get; }
    public IPEndPoint TargetEndpoint { get; }
    public bool IsOpen { get; private set; } = true;

    /// <summary>Fires when T→O data arrives from the target.</summary>
    public event Action<ReadOnlyMemory<byte>>? DataReceived;

    /// <summary>Number of O→T packets sent.</summary>
    public int SendCount { get; private set; }

    /// <summary>Number of T→O packets received.</summary>
    public int ReceiveCount { get; private set; }

    internal ScannerConnection(
        EipScanner scanner,
        EipUdpTransport udp,
        ForwardOpenConfig config,
        IPEndPoint targetEndpoint,
        uint otoTConnectionId,
        uint ttoOConnectionId,
        ushort connectionSerial,
        ushort originatorVendor,
        uint originatorSerial)
    {
        _scanner = scanner;
        _udp = udp;
        Config = config;
        TargetEndpoint = targetEndpoint;
        OtoTConnectionId = otoTConnectionId;
        TtoOConnectionId = ttoOConnectionId;
        ConnectionSerial = connectionSerial;
        OriginatorVendor = originatorVendor;
        OriginatorSerial = originatorSerial;

        // O→T: connection size = seq(2) + run/idle(4) + data
        _consumedData = new byte[config.ConsumedSize];
        // T→O: connection size = seq(2) + data (no run/idle from target)
        _producedData = new byte[config.ProducedSize];
    }

    internal void Start()
    {
        // Subscribe to UDP receives — typed messages from the transport's CPF parser
        _udp.MessageReceived += OnUdpMessageReceived;

        // Start O→T production timer
        var interval = TimeSpan.FromMicroseconds(Config.Rpi);
        if (interval < TimeSpan.FromMilliseconds(1))
            interval = TimeSpan.FromMilliseconds(1);
        _productionTimer = new Timer(_ => ProduceData(), null, interval, interval);
    }

    /// <summary>Read the latest T→O data received from the target.</summary>
    public ReadOnlySpan<byte> GetProducedData() => _producedData;

    /// <summary>Copy T→O data to a caller-owned buffer.</summary>
    public void CopyProducedDataTo(Span<byte> destination) =>
        _producedData.AsSpan().CopyTo(destination);

    /// <summary>Set the O→T data to send to the target on the next cycle.</summary>
    public void SetConsumedData(ReadOnlySpan<byte> data) =>
        data.Slice(0, Math.Min(data.Length, _consumedData.Length)).CopyTo(_consumedData);

    /// <summary>Write a typed value into the O→T data buffer.</summary>
    public void Write<T>(int byteOffset, T value) where T : unmanaged =>
        System.Runtime.CompilerServices.Unsafe.WriteUnaligned(ref _consumedData[byteOffset], value);

    /// <summary>Read a typed value from the T→O data buffer.</summary>
    public T Read<T>(int byteOffset = 0) where T : unmanaged =>
        System.Runtime.CompilerServices.Unsafe.ReadUnaligned<T>(ref _producedData[byteOffset]);

    private void ProduceData()
    {
        if (!IsOpen) return;

        try
        {
            ProduceDataCore();
        }
        catch { } // Timer thread — swallow send errors
    }

    private void ProduceDataCore()
    {
        _encapSeqNum++;

        byte[] ioData;
        if (Config.IsClass1)
        {
            _cipSeqCount++;
            // O→T from originator: seq(2) + run/idle(4) + data
            ioData = new byte[2 + 4 + _consumedData.Length];
            BinaryPrimitives.WriteUInt16LittleEndian(ioData, _cipSeqCount);
            BinaryPrimitives.WriteUInt32LittleEndian(ioData.AsSpan(2), 0x00000001); // RUN
            _consumedData.CopyTo(ioData.AsSpan(6));
        }
        else
        {
            ioData = new byte[_consumedData.Length];
            _consumedData.CopyTo(ioData, 0);
        }

        _udp.SendIoData(TargetEndpoint, OtoTConnectionId, _encapSeqNum, ioData);
        SendCount++;
    }

    private void OnUdpMessageReceived(IMessage message)
    {
        if (message is not CpfConnectedDataMessage cpf) return;
        if (cpf.ConnectionId != TtoOConnectionId) return;
        if (!IsOpen) return;

        // T→O from target: seq(2) + data (no run/idle)
        ReadOnlyMemory<byte> ioData;
        if (Config.IsClass1 && cpf.Payload.Length >= 2)
            ioData = cpf.Payload.Slice(2);
        else
            ioData = cpf.Payload;

        int copyLen = Math.Min(ioData.Length, _producedData.Length);
        ioData.Slice(0, copyLen).Span.CopyTo(_producedData);
        ReceiveCount++;
        DataReceived?.Invoke(ioData);
    }

    /// <summary>Send Forward Close and stop I/O.</summary>
    public async Task CloseAsync(CancellationToken ct = default)
    {
        if (!IsOpen) return;
        IsOpen = false;

        _productionTimer?.Dispose();
        _udp.MessageReceived -= OnUdpMessageReceived;

        await _scanner.ForwardCloseAsync(ConnectionSerial, OriginatorVendor, OriginatorSerial, ct);
    }

    public ValueTask DisposeAsync()
    {
        IsOpen = false;
        _productionTimer?.Dispose();
        _udp.MessageReceived -= OnUdpMessageReceived;
        return ValueTask.CompletedTask;
    }
}
