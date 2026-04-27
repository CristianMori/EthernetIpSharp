using System.Net;

namespace EipSim.Protocol;

/// <summary>
/// UDP I/O transport abstraction for EtherNet/IP Class 0/1 data.
/// Implement to provide custom transport or mock for testing.
/// </summary>
public interface IEipUdpTransport : IAsyncDisposable
{
    /// <summary>Fired when I/O data arrives. Parameters: connectionId, data.</summary>
    event Action<uint, ReadOnlyMemory<byte>>? DataReceived;

    /// <summary>Fired with sender endpoint when I/O data arrives. Parameters: connectionId, senderEndpoint.</summary>
    event Action<uint, IPEndPoint>? DataReceivedWithSender;

    /// <summary>Start listening for UDP packets.</summary>
    Task StartAsync(CancellationToken ct);

    /// <summary>Send I/O data to a remote endpoint.</summary>
    void SendIoData(IPEndPoint destination, uint connectionId, uint encapSeqNum, ReadOnlySpan<byte> data);
}
