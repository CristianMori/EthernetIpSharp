using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Protocol.Tests;

public class EipScannerConnectTimeoutTests
{
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(300);
    private static readonly TimeSpan Budget = Short + TimeSpan.FromSeconds(1);

    // A connect that never completes until its token is cancelled: a
    // deterministic stand-in for a black-holed SYN, independent of the
    // network the tests run on.
    private static ValueTask Hang(CancellationToken ct) => new(Task.Delay(Timeout.Infinite, ct));

    [Fact]
    public void DefaultConnectTimeout_IsFiveSeconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), new EipScanner().ConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(5), EipScanner.DefaultConnectTimeout);
    }

    [Fact]
    public void ConnectTimeout_InfiniteMapsToNull_AndNonPositiveRejected()
    {
        var c = new EipScanner();
        c.ConnectTimeout = Timeout.InfiniteTimeSpan;
        Assert.Null(c.ConnectTimeout);
        c.ConnectTimeout = null;
        Assert.Null(c.ConnectTimeout);
        Assert.Throws<ArgumentOutOfRangeException>(() => c.ConnectTimeout = TimeSpan.Zero);
    }

    [Fact]
    public async Task Helper_HangingConnect_ThrowsTimeoutWithinBound_AndDisposesSocket()
    {
        var tcp = new TcpClient();
        var sw = Stopwatch.StartNew();
        var ex = await Assert.ThrowsAsync<TimeoutException>(() =>
            TcpConnectHelper.ConnectAsync(tcp, Hang, "10.255.255.1", 44818, Short, default));
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
        Assert.Contains("10.255.255.1:44818", ex.Message);
        Assert.Contains("300", ex.Message);
        Assert.Null(tcp.Client); // disposed
    }

    [Fact]
    public async Task Helper_TimeoutDisabled_DoesNotFire_AndCallerCancelIsOperationCanceled()
    {
        using var cts = new CancellationTokenSource();
        var tcp = new TcpClient();
        var task = TcpConnectHelper.ConnectAsync(tcp, Hang, "h", 1, null, cts.Token);
        await Task.Delay(Short * 2);
        Assert.False(task.IsCompleted, "disabled timeout must not fire");
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.Null(tcp.Client);
    }

    [Fact]
    public async Task Helper_CallerCancelBeforeTimeout_IsOperationCanceledNotTimeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var tcp = new TcpClient();
        var ex = await Record.ExceptionAsync(() =>
            TcpConnectHelper.ConnectAsync(tcp, Hang, "h", 1, TimeSpan.FromSeconds(30), cts.Token));
        Assert.IsAssignableFrom<OperationCanceledException>(ex);
    }

    [Fact]
    public async Task Connect_Refused_StillFailsWithSocketException_NotTimeout()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        // Default 5 s timeout: Windows retries a refused loopback SYN for ~2 s
        var c = new EipScanner();
        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAsync<SocketException>(() => c.ConnectAsync(IPAddress.Loopback, port));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(4.5), $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task Connect_BlackholeAddress_FailsWithinBound()
    {
        // 10.255.255.1 is normally unrouted and silently dropped, so the
        // connect hangs. Networks without a route reject it immediately
        // (SocketException); either way the call must return within the bound.
        var c = new EipScanner { ConnectTimeout = Short };
        var sw = Stopwatch.StartNew();
        var ex = await Record.ExceptionAsync(() => c.ConnectAsync(IPAddress.Parse("10.255.255.1")));
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
        Assert.True(ex is TimeoutException or SocketException, ex?.ToString());
        Assert.False(c.IsConnected);
    }

    [Fact]
    public async Task Connect_LoopbackServer_ConnectsWithDefaultTimeout()
    {
        using var server = new SilentTargetServer();
        await using var c = new EipScanner();
        await c.ConnectAsync(IPAddress.Loopback, server.Port);
        Assert.True(c.IsConnected);
    }
}
