using System.Buffers;
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
/// Mirrors UdpSocket's role: socket transport without any protocol logic.
/// </summary>
public sealed class TcpSocket : IAsyncDisposable
{
    /// <summary>Fired (on a per-client thread) when a new client connects. Hand back the connection object so caller can wire up send/receive.</summary>
    public event Action<TcpSocketConnection>? ClientConnected;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Thread? _acceptThread;

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
            try
            {
                var client = _listener!.AcceptTcpClient();
                var conn = new TcpSocketConnection(client, _cts.Token);
                ClientConnected?.Invoke(conn);
                conn.Start();
            }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { /* listener was closed mid-accept */ break; }
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
        _acceptThread?.Join(500);
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
    private bool _disposed;

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

    private void ReadLoop()
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while (!_ct.IsCancellationRequested && !_disposed)
            {
                int n;
                try { n = _stream.Read(buf, 0, buf.Length); }
                catch (IOException) { break; }
                catch (ObjectDisposedException) { break; }

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
        }
    }

    /// <summary>Send bytes on this connection. Synchronous.</summary>
    public void Send(ReadOnlySpan<byte> data)
    {
        if (_disposed) return;
        try { _stream.Write(data); }
        catch (IOException) { Dispose(); }
        catch (ObjectDisposedException) { Dispose(); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _stream.Dispose(); } catch { }
        try { _client.Dispose(); } catch { }
    }
}
