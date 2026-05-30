using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// Pure UDP socket abstraction. No protocol knowledge.
///
/// Two threads:
///   - RX thread:       ReceiveFrom into pooled buffer, enqueue, repeat
///   - Dispatch thread: dequeue, fire PacketReceived, recycle buffer
///
/// Decoupling receive from dispatch means a slow event handler never
/// causes us to miss packets at the socket layer (up to the configured
/// queue depth + OS socket buffer).
/// </summary>
public sealed class UdpSocket : IAsyncDisposable
{
    /// <summary>Fired (on dispatch thread) for each received UDP packet.</summary>
    public event Action<ReadOnlyMemory<byte>, IPEndPoint>? PacketReceived;

    private UdpClient? _client;
    private Thread? _rxThread;
    private Thread? _dispatchThread;
    private CancellationTokenSource? _cts;

    // SPSC handoff between RX thread (single producer) and dispatch thread
    // (single consumer). BlockingCollection wraps a ConcurrentQueue and gives
    // us a built-in blocking Take + cooperative shutdown via CompleteAdding.
    private readonly BlockingCollection<RxPacket> _queue = new(new ConcurrentQueue<RxPacket>());

    private readonly record struct RxPacket(byte[] Buffer, int Length, IPEndPoint RemoteEndpoint);

    /// <summary>Bind the socket and start the RX + dispatch threads.</summary>
    public Task StartAsync(IPEndPoint bindEndpoint, CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _client = new UdpClient();
        // Generous buffers so processing delays can't cause OS-level drops.
        _client.Client.ReceiveBufferSize = 4 * 1024 * 1024;
        _client.Client.SendBufferSize = 1 * 1024 * 1024;

        // Windows default: an ICMP port-unreachable from a prior send makes the
        // next recv throw WSAECONNRESET. Disable that so a transient PLC stall
        // can't silently kill the receive loop.
        if (OperatingSystem.IsWindows())
        {
            const int SIO_UDP_CONNRESET = -1744830452; // 0x9800000C
            _client.Client.IOControl(SIO_UDP_CONNRESET, new byte[] { 0 }, null);
        }

        _client.Client.Bind(bindEndpoint);

        _rxThread = new Thread(RxLoop)
        {
            IsBackground = true,
            Name = "UDP-Rx",
            Priority = ThreadPriority.AboveNormal,
        };
        _rxThread.Start();

        _dispatchThread = new Thread(DispatchLoop)
        {
            IsBackground = true,
            Name = "UDP-Dispatch",
            Priority = ThreadPriority.AboveNormal,
        };
        _dispatchThread.Start();

        return Task.CompletedTask;
    }

    /// <summary>Send a UDP packet. Synchronous; safe to call from any thread.</summary>
    public void Send(IPEndPoint destination, ReadOnlySpan<byte> data)
    {
        _client?.Client.SendTo(data, SocketFlags.None, destination);
    }

    private void RxLoop()
    {
        var ct = _cts!.Token;
        var sock = _client!.Client;
        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);

        while (!ct.IsCancellationRequested)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(2048);
            try
            {
                int len = sock.ReceiveFrom(buf, ref remote);
                if (len > 0)
                {
                    // Copy endpoint — ReceiveFrom mutates the passed-in instance.
                    var endpoint = new IPEndPoint(((IPEndPoint)remote).Address,
                                                  ((IPEndPoint)remote).Port);
                    _queue.Add(new RxPacket(buf, len, endpoint));
                    continue; // ownership of buf transferred to dispatch thread
                }
            }
            catch (OperationCanceledException) { ArrayPool<byte>.Shared.Return(buf); break; }
            catch (ObjectDisposedException) { ArrayPool<byte>.Shared.Return(buf); break; }
            catch (InvalidOperationException) { ArrayPool<byte>.Shared.Return(buf); break; } // _queue.CompleteAdding called
            catch (SocketException) { /* transient */ }

            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    private void DispatchLoop()
    {
        var ct = _cts!.Token;
        try
        {
            foreach (var pkt in _queue.GetConsumingEnumerable(ct))
            {
                try { PacketReceived?.Invoke(pkt.Buffer.AsMemory(0, pkt.Length), pkt.RemoteEndpoint); }
                catch { /* swallow handler exceptions so dispatch thread keeps running */ }
                finally { ArrayPool<byte>.Shared.Return(pkt.Buffer); }
            }
        }
        catch (OperationCanceledException) { /* cancellation requested */ }
    }

    public ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        try { _queue.CompleteAdding(); } catch (ObjectDisposedException) { } // wake dispatch loop

        // Wait briefly for the threads to exit before tearing down their state.
        _rxThread?.Join(500);
        _dispatchThread?.Join(500);

        _client?.Dispose();
        _queue.Dispose();
        _cts?.Dispose();
        return ValueTask.CompletedTask;
    }
}
