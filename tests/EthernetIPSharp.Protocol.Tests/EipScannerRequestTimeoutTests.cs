using System.Diagnostics;
using System.Net;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Protocol.Tests;

public class EipScannerRequestTimeoutTests
{
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(300);
    private static readonly TimeSpan Budget = Short + TimeSpan.FromSeconds(1);
    private static readonly byte[] Path = { 0x20, 0x01, 0x24, 0x01 };

    [Fact]
    public void DefaultRequestTimeout_IsFiveSeconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), new EipScanner().RequestTimeout);
        Assert.Equal(TimeSpan.FromSeconds(5), EipScanner.DefaultRequestTimeout);
    }

    [Fact]
    public void RequestTimeout_InfiniteMapsToNull_AndNonPositiveRejected()
    {
        var s = new EipScanner { RequestTimeout = Timeout.InfiniteTimeSpan };
        Assert.Null(s.RequestTimeout);
        Assert.Throws<ArgumentOutOfRangeException>(() => s.RequestTimeout = TimeSpan.Zero);
    }

    [Fact]
    public async Task SendExplicit_NoReply_ThrowsTimeoutAndResetsSession()
    {
        using var server = new SilentTargetServer();
        await using var scanner = new EipScanner { RequestTimeout = Short };
        await scanner.ConnectAsync(IPAddress.Loopback, server.Port);
        Assert.True(scanner.IsConnected);

        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(
            () => scanner.SendExplicitAsync(0x0E, Path, Array.Empty<byte>()));
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
        Assert.False(scanner.IsConnected);
        Assert.Equal(0u, scanner.SessionHandle);
    }

    [Fact]
    public async Task RegisterSession_NoReply_ThrowsTimeout()
    {
        using var server = new SilentTargetServer(answerRegister: false);
        await using var scanner = new EipScanner { RequestTimeout = Short };
        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(
            () => scanner.ConnectAsync(IPAddress.Loopback, server.Port));
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task ConnectedExplicit_DisposeWithSilentTarget_ReturnsWithinTimeout()
    {
        using var server = new SilentTargetServer(rrReplies: 1);
        await using var scanner = new EipScanner { RequestTimeout = Short };
        await scanner.ConnectAsync(IPAddress.Loopback, server.Port);
        var conn = await scanner.OpenExplicitAsync();

        var sw = Stopwatch.StartNew();
        await conn.DisposeAsync(); // Forward_Close gets no reply
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
        Assert.False(scanner.IsConnected);
    }

    [Fact]
    public async Task ConnectedExplicit_SendUnitData_NoReply_ThrowsTimeout()
    {
        using var server = new SilentTargetServer(rrReplies: 1);
        await using var scanner = new EipScanner { RequestTimeout = Short };
        await scanner.ConnectAsync(IPAddress.Loopback, server.Port);
        var conn = await scanner.OpenExplicitAsync();
        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(
            () => conn.SendRawAsync(0x0E, Path));
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CallerCancellation_StaysOperationCanceled(bool infinite)
    {
        using var server = new SilentTargetServer();
        await using var scanner = new EipScanner
        {
            RequestTimeout = infinite ? Timeout.InfiniteTimeSpan : TimeSpan.FromSeconds(30),
        };
        await scanner.ConnectAsync(IPAddress.Loopback, server.Port);
        using var cts = new CancellationTokenSource(Short);
        var ex = await Record.ExceptionAsync(
            () => scanner.SendExplicitAsync(0x0E, Path, Array.Empty<byte>(), cts.Token));
        Assert.IsAssignableFrom<OperationCanceledException>(ex);
        Assert.IsNotType<TimeoutException>(ex);
    }
}
