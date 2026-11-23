using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Protocol.Tests;

/// <summary>
/// Disposing a socket must return promptly even when a receive is blocked
/// with no traffic, and must close live client connections.
/// </summary>
public class SocketStopTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(1);

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    private static async Task AssertCompletesAsync(Func<ValueTask> dispose, string what)
    {
        var sw = Stopwatch.StartNew();
        var task = Task.Run(async () => await dispose());
        var winner = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(10)));
        Assert.True(winner == task, $"{what}: DisposeAsync did not complete");
        await task;
        Assert.True(sw.Elapsed < Limit, $"{what}: DisposeAsync took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task UdpSocket_DisposeWhileBlockedInReceive_CompletesPromptly()
    {
        var udp = new UdpSocket();
        await udp.StartAsync(new IPEndPoint(IPAddress.Loopback, 0), CancellationToken.None);
        await Task.Delay(200); // let the receive loop block

        await AssertCompletesAsync(udp.DisposeAsync, "UdpSocket");
    }

    [Fact]
    public async Task UdpSocket_StillDeliversPacketsBeforeDispose()
    {
        int port = FreePort();
        var udp = new UdpSocket();
        var got = new TaskCompletionSource<byte[]>();
        udp.PacketReceived += (mem, ep) => got.TrySetResult(mem.ToArray());
        await udp.StartAsync(new IPEndPoint(IPAddress.Loopback, port), CancellationToken.None);

        using (var sender = new UdpClient())
            sender.Send(new byte[] { 1, 2, 3 }, 3, new IPEndPoint(IPAddress.Loopback, port));

        var done = await Task.WhenAny(got.Task, Task.Delay(5000));
        Assert.Same(got.Task, done);
        Assert.Equal(new byte[] { 1, 2, 3 }, await got.Task);

        await AssertCompletesAsync(udp.DisposeAsync, "UdpSocket");
    }

    [Fact]
    public async Task TcpSocket_DisposeWithIdleClient_ClosesClientPromptly()
    {
        int port = FreePort();
        var tcp = new TcpSocket();
        var closed = new TaskCompletionSource();
        tcp.ClientConnected += c => c.Closed += _ => closed.TrySetResult();
        await tcp.StartAsync(new IPEndPoint(IPAddress.Loopback, port), CancellationToken.None);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var stream = client.GetStream();
        await Task.Delay(200); // let the server read thread block

        await AssertCompletesAsync(tcp.DisposeAsync, "TcpSocket");

        // Server side saw the connection end.
        Assert.Same(closed.Task, await Task.WhenAny(closed.Task, Task.Delay(2000)));

        // Client sees EOF (or a reset).
        var buf = new byte[16];
        int n;
        try { n = await stream.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(2)); }
        catch (IOException) { n = 0; }
        Assert.Equal(0, n);
    }

    [Fact]
    public async Task TcpSocket_DisposeWithNoClients_CompletesPromptly()
    {
        var tcp = new TcpSocket();
        await tcp.StartAsync(new IPEndPoint(IPAddress.Loopback, 0), CancellationToken.None);
        await Task.Delay(200);

        await AssertCompletesAsync(tcp.DisposeAsync, "TcpSocket");
    }
}
