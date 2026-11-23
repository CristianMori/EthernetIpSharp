using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// Pure TCP listening socket. No protocol knowledge.
///
/// Owns a TcpListener and accepts client connections on a dedicated accept
/// thread. Each accepted client runs on its own thread that reads bytes
/// and fires BytesReceived for each chunk. Consumers handle framing
/// (accumulate into a buffer, parse messages with an IMessageManager).
///
/// Live connections are tracked so that disposing the socket closes them
/// and joins their read threads.
///
/// Mirrors UdpSocket's role: socket transport without any protocol logic.
/// </summary>
public sealed class TcpSocket : IAsyncDisposable
{
    /// <summary>Fired (on a per-client thread) when a new client connects. Hand back the connection object so caller can wire up send/receive.</summary>
    public event Action<TcpSocketConnection>? ClientConnected;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Thread? _acceptThread;
    private readonly ConcurrentDictionary<TcpSocketConnection, byte> _connections = new();

    /// <summary>Bind + listen + start the accept thread.</summary>
    public Task StartAsync(IPEndPoint bindEndpoint, CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _listener = new TcpListener(bindEndpoint);
        _listener.Start();

        _acceptThread = new Thread(AcceptLoop)
        {
            IsBackground = true,
            Name = "TCP-Accept",
        };
        _acceptThread.Start();
        return Task.CompletedTask;
    }

    private void AcceptLoop()
    {
        var ct = _cts!.Token;
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = _listener!.AcceptTcpClient(); }
            catch (ObjectDisposedException) { break; }
            // Listener stopped mid-accept (Interrupted / OperationAborted) or failed.
            catch (SocketException) { break; }
            catch (InvalidOperationException) { break; }

            TcpSocketConnection conn;
            try { conn = new TcpSocketConnection(client, ct); }
            catch { try { client.Dispose(); } catch { } continue; }

            conn.Ended = c => _connections.TryRemove(c, out _);
            _connections[conn] = 0;

            // Accepted just as disposal started (accept can return normally after Stop).
            if (ct.IsCancellationRequested)
            {
                conn.Dispose();
                _connections.TryRemove(conn, out _);
                break;
            }

            try { ClientConnected?.Invoke(conn); }
            catch { conn.Dispose(); _connections.TryRemove(conn, out _); continue; }
            conn.Start();
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
        if (_acceptThread is { } at && at != Thread.CurrentThread) at.Join(500);

        // Close every live client (wakes their blocked reads), then join the
        // read threads within one shared bounded wait.
        var live = _connections.Keys.ToArray();
        foreach (var c in live)
            c.Dispose();
        var deadline = Environment.TickCount64 + 1000;
        foreach (var c in live)
        {
            var left = (int)Math.Max(0, deadline - Environment.TickCount64);
            c.JoinReader(left);
        }
        _connections.Clear();

        _cts?.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// One accepted TCP client. Owns a per-client read thread; raises
/// BytesReceived for each chunk read from the socket. Synchronous Send.
/// </summary>
public sealed class TcpSocketConnection : IDisposable
{
    /// <summary>Fired (on the per-client read thread) with each chunk of bytes received.</summary>
    public event Action<TcpSocketConnection, ReadOnlyMemory<byte>>? BytesReceived;

    /// <summary>Fired (on the per-client read thread) when the connection closes (peer disconnect or error).</summary>
    public event Action<TcpSocketConnection>? Closed;

    public IPEndPoint LocalEndpoint { get; }
    public IPEndPoint RemoteEndpoint { get; }

    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private readonly CancellationToken _ct;
    private Thread? _readThread;
    private int _disposed;

    /// <summary>Owner hook: called once when the read loop ends, so the owner can drop its reference.</summary>
    internal Action<TcpSocketConnection>? Ended { get; set; }

    internal TcpSocketConnection(TcpClient client, CancellationToken ct)
    {
        _client = client;
        _stream = client.GetStream();
        _ct = ct;
        LocalEndpoint = (IPEndPoint)client.Client.LocalEndPoint!;
        RemoteEndpoint = (IPEndPoint)client.Client.RemoteEndPoint!;
    }

    internal void Start()
    {
        _readThread = new Thread(ReadLoop)
        {
            IsBackground = true,
            Name = $"TCP-Read-{RemoteEndpoint}",
        };
        _readThread.Start();
    }

    internal void JoinReader(int millisecondsTimeout)
    {
        var t = _readThread;
        if (t != null && t != Thread.CurrentThread) t.Join(millisecondsTimeout);
    }

    private void ReadLoop()
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while (!_ct.IsCancellationRequested && Volatile.Read(ref _disposed) == 0)
            {
                int n;
                try { n = _stream.Read(buf, 0, buf.Length); }
                catch (IOException) { break; }
                catch (ObjectDisposedException) { break; }
                catch (SocketException) { break; }

                if (n == 0) break; // peer closed
                try { BytesReceived?.Invoke(this, buf.AsMemory(0, n)); }
                catch { /* swallow handler exceptions so the read loop keeps running */ }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
            try { Closed?.Invoke(this); } catch { }
            Dispose();
            try { Ended?.Invoke(this); } catch { }
        }
    }

    /// <summary>Send bytes on this connection. Synchronous.</summary>
    public void Send(ReadOnlySpan<byte> data)
    {
        if (Volatile.Read(ref _disposed) != 0) return;
        try { _stream.Write(data); }
        catch (IOException) { Dispose(); }
        catch (ObjectDisposedException) { Dispose(); }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _stream.Dispose(); } catch { }
        try { _client.Dispose(); } catch { }
    }
}
