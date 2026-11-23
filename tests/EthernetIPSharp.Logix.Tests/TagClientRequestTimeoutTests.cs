using System.Diagnostics;
using EthernetIPSharp.Logix;
using EthernetIPSharp.Protocol.Tests;

namespace EthernetIPSharp.Logix.Tests;

public class TagClientRequestTimeoutTests
{
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(300);
    private static readonly TimeSpan Budget = Short + TimeSpan.FromSeconds(1);

    [Fact]
    public void DefaultRequestTimeout_IsFiveSeconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), new TagClient("127.0.0.1").RequestTimeout);
        Assert.Equal(TimeSpan.FromSeconds(5), TagClient.DefaultRequestTimeout);
    }

    [Fact]
    public void RequestTimeout_InfiniteMapsToNull_AndNonPositiveRejected()
    {
        var c = new TagClient("127.0.0.1") { RequestTimeout = Timeout.InfiniteTimeSpan };
        Assert.Null(c.RequestTimeout);
        Assert.Throws<ArgumentOutOfRangeException>(() => c.RequestTimeout = TimeSpan.Zero);
    }

    [Fact]
    public async Task Read_NoReply_ThrowsTimeoutAndResetsSession()
    {
        using var server = new SilentTargetServer();
        await using var client = new TagClient("127.0.0.1", server.Port) { RequestTimeout = Short };
        await client.ConnectAsync();
        Assert.True(client.IsConnected);

        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(() => client.ReadAsync<int>("Foo"));
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
        Assert.False(client.IsConnected);
        Assert.Equal(0u, client.SessionHandle);
    }

    [Fact]
    public async Task RegisterSession_NoReply_ThrowsTimeout()
    {
        using var server = new SilentTargetServer(answerRegister: false);
        await using var client = new TagClient("127.0.0.1", server.Port) { RequestTimeout = Short };
        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(() => client.ConnectAsync());
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task Class3_ReadNoReply_ThrowsTimeout()
    {
        using var server = new SilentTargetServer(rrReplies: 1);
        await using var client = new TagClient("127.0.0.1", server.Port, useConnected: true) { RequestTimeout = Short };
        await client.ConnectAsync(); // Forward_Open answered
        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(() => client.ReadAsync<int>("Foo"));
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task Class3_ForwardOpenNoReply_ThrowsTimeout()
    {
        using var server = new SilentTargetServer();
        await using var client = new TagClient("127.0.0.1", server.Port, useConnected: true) { RequestTimeout = Short };
        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(() => client.ConnectAsync());
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task Class3_DisconnectWithSilentTarget_ReturnsWithinTimeout()
    {
        using var server = new SilentTargetServer(rrReplies: 1);
        var client = new TagClient("127.0.0.1", server.Port, useConnected: true) { RequestTimeout = Short };
        await client.ConnectAsync();

        var sw = Stopwatch.StartNew();
        await client.DisposeAsync(); // Forward_Close gets no reply
        Assert.True(sw.Elapsed < Budget, $"took {sw.Elapsed}");
        Assert.False(client.IsConnected);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CallerCancellation_StaysOperationCanceled(bool infinite)
    {
        using var server = new SilentTargetServer();
        await using var client = new TagClient("127.0.0.1", server.Port)
        {
            RequestTimeout = infinite ? Timeout.InfiniteTimeSpan : TimeSpan.FromSeconds(30),
        };
        await client.ConnectAsync();
        using var cts = new CancellationTokenSource(Short);
        var ex = await Record.ExceptionAsync(() => client.ReadAsync<int>("Foo", cts.Token));
        Assert.IsAssignableFrom<OperationCanceledException>(ex);
        Assert.IsNotType<TimeoutException>(ex);
    }
}
