using System.Net;
using System.Reflection;
using EthernetIPSharp.Protocol;
using EthernetIPSharp.Protocol.Messages;
using EthernetIPSharp.Safety;
using Xunit;

namespace EthernetIPSharp.Safety.Tests;

/// <summary>
/// Minimal UDP transport stub for CloseAsync / field-access tests. It
/// records nothing and sends nothing — real I/O is not exercised.
/// </summary>
file sealed class StubUdpTransport : IEipUdpTransport
{
    public event Action<IMessage>? MessageReceived { add { } remove { } }
    public Task StartAsync(CancellationToken ct) => Task.CompletedTask;
    public void Send(ISerializableMessage message) { }
    public void SendIoData(IPEndPoint destination, uint connectionId, uint encapSeqNum,
        ReadOnlySpan<byte> data) { }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

/// <summary>
/// Regression tests for the cross-thread field access scheme in
/// <see cref="SafetyScannerConnection"/>. The production thread encodes
/// safety frames while the UDP dispatch thread (and user code) may be
/// writing shared fields; without proper ordering the producer could
/// observe a torn multi-byte payload or stale ordering between
/// <c>_consumerActive</c> and <c>_productionStartTicks</c>.
/// </summary>
public class SafetyScannerConcurrencyTests
{
    /// <summary>
    /// Build a <see cref="SafetyScannerConnection"/> around uninitialized
    /// dependencies via reflection. We only exercise <c>SetOutputData</c>
    /// and the private <c>_outputData</c> field — no actual Forward Open or
    /// UDP I/O runs — so the null transport and scanner are not accessed.
    /// </summary>
    private static SafetyScannerConnection NewForFieldAccess(int outputSize,
        IEipUdpTransport? udp = null)
    {
        var ctor = typeof(SafetyScannerConnection).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            types: new[]
            {
                typeof(EthernetIPSharp.Protocol.EipScanner),
                typeof(IEipUdpTransport),
                typeof(SafetyFormat),
            },
            modifiers: null);
        Assert.NotNull(ctor);

        var conn = (SafetyScannerConnection)ctor!.Invoke(
            new object?[] { null, udp, SafetyFormat.Base });

        // Seed the backing buffer so SetOutputData's copy-on-swap sees a
        // fixed-length target to copy into.
        var fld = typeof(SafetyScannerConnection).GetField(
            "_outputData", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(fld);
        fld!.SetValue(conn, new byte[outputSize]);
        return conn;
    }

    private static void SetPrivate(SafetyScannerConnection conn, string name, object? value)
    {
        var fld = typeof(SafetyScannerConnection).GetField(
            name, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(fld);
        fld!.SetValue(conn, value);
    }

    private static byte[] ReadOutputData(SafetyScannerConnection conn)
    {
        var fld = typeof(SafetyScannerConnection).GetField(
            "_outputData", BindingFlags.NonPublic | BindingFlags.Instance);
        return (byte[])fld!.GetValue(conn)!;
    }

    [Fact]
    public void SetOutputData_IsTearFreeUnderConcurrentReads()
    {
        // Payload invariant: byte[i] = (byte)((seed + i) & 0xFF). Any snapshot
        // the "producer" reads must satisfy that invariant end-to-end. A torn
        // read would show bytes from two different seeds and fail the check.
        const int Size = 32;
        const int Iterations = 1000;

        var conn = NewForFieldAccess(Size);

        var stop = new ManualResetEventSlim(false);
        Exception? firstFailure = null;

        var reader = new Thread(() =>
        {
            try
            {
                while (!stop.IsSet)
                {
                    var snapshot = ReadOutputData(conn);
                    if (snapshot.Length == 0) continue;
                    byte seed = snapshot[0];
                    for (int i = 1; i < snapshot.Length; i++)
                    {
                        byte expected = (byte)((seed + i) & 0xFF);
                        if (snapshot[i] != expected)
                        {
                            Interlocked.CompareExchange(ref firstFailure,
                                new Xunit.Sdk.XunitException(
                                    $"Torn payload: seed=0x{seed:X2} snapshot[{i}]=0x{snapshot[i]:X2} expected=0x{expected:X2}"),
                                null);
                            return;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Interlocked.CompareExchange(ref firstFailure, ex, null);
            }
        }) { IsBackground = true, Name = "FieldAccess-Reader" };
        reader.Start();

        var scratch = new byte[Size];
        for (int iter = 0; iter < Iterations; iter++)
        {
            byte seed = (byte)(iter & 0xFF);
            for (int i = 0; i < Size; i++) scratch[i] = (byte)((seed + i) & 0xFF);
            conn.SetOutputData(scratch);
            Thread.SpinWait(50);
        }

        stop.Set();
        reader.Join(2000);

        if (firstFailure != null) throw firstFailure;
    }

    [Fact]
    public async Task CloseAsync_JoinsProductionThreadCleanly()
    {
        // Spin a stand-in production thread, hand its handle to the
        // connection via reflection, then call CloseAsync in a loop.
        // Before the Join fix CloseAsync returned while the thread was
        // still iterating; now the thread MUST have exited by the time
        // CloseAsync returns (modulo the 500 ms Join budget).
        for (int iter = 0; iter < 10; iter++)
        {
            var conn = NewForFieldAccess(outputSize: 8, udp: new StubUdpTransport());
            var cts = new CancellationTokenSource();
            var started = new ManualResetEventSlim(false);
            var thread = new Thread(() =>
            {
                started.Set();
                while (!cts.Token.IsCancellationRequested)
                    Thread.SpinWait(50);
            })
            { IsBackground = true, Name = "StubProduction" };

            SetPrivate(conn, "_productionCts", cts);
            SetPrivate(conn, "_productionThread", thread);
            SetPrivate(conn, "_isOpen", true);

            thread.Start();
            Assert.True(started.Wait(1000));

            await conn.CloseAsync();

            // Thread must have exited by the time CloseAsync returned. If
            // CloseAsync skipped the Join, the thread could still be alive
            // here.
            Assert.False(thread.IsAlive,
                $"Production thread still alive after CloseAsync (iteration {iter})");
        }
    }

    [Fact]
    public void SetOutputData_PreservesBufferLength()
    {
        // Copy-on-swap must preserve the original backing buffer size so
        // SafetyFrameCodec.Encode continues to see the negotiated
        // ConsumedDataSize. Oversized writes get truncated, undersized ones
        // zero-pad.
        var conn = NewForFieldAccess(8);

        conn.SetOutputData(new byte[] { 1, 2, 3, 4 });
        var afterShort = ReadOutputData(conn);
        Assert.Equal(8, afterShort.Length);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 0, 0, 0, 0 }, afterShort);

        conn.SetOutputData(new byte[] { 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 });
        var afterLong = ReadOutputData(conn);
        Assert.Equal(8, afterLong.Length);
        Assert.All(afterLong, b => Assert.Equal((byte)9, b));
    }
}
