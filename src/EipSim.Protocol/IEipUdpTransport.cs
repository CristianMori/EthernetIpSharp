using System.Net;

namespace EipSim.Protocol;

/// <summary>
/// UDP I/O transport abstraction.
/// Mock for testing I/O connection lifecycle without actual sockets.
/// </summary>
public interface IEipUdpTransport : IAsyncDisposable
{
    event Action<uint, ReadOnlyMemory<byte>>? DataReceived;
    Task StartAsync(CancellationToken ct);
    void SendIoData(IPEndPoint destination, uint connectionId, uint encapSeqNum, ReadOnlySpan<byte> data);
}
