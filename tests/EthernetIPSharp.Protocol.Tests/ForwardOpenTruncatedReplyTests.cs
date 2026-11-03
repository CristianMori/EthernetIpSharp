using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Protocol.Tests;

/// <summary>
/// Regression test for the ForwardOpenAsync response-size guard. A hostile
/// or malformed target that returned a Forward_Open success reply with
/// fewer than 8 payload bytes would otherwise trip
/// <see cref="ArgumentOutOfRangeException"/> out of
/// <c>BinaryPrimitives.ReadUInt32LittleEndian</c>, surfaced through a
/// public async entry point as an unrelated exception type.
/// </summary>
public class ForwardOpenTruncatedReplyTests
{
    [Fact]
    public async Task ForwardOpenAsync_TruncatedResponsePayload_ThrowsInvalidOperation()
    {
        using var listener = new HostileTargetServer(replyPayloadBytes: 4);
        listener.Start();

        var scanner = new EipScanner();
        await scanner.ConnectAsync(IPAddress.Loopback, listener.Port);

        var cfg = new ForwardOpenConfig
        {
            ConfigAssembly = 150,
            ConsumedAssembly = 101,
            ProducedAssembly = 100,
            ConsumedSize = 16,
            ProducedSize = 16,
            Rpi = 50000,
            TimeoutMultiplier = 0,
            TransportClass = 0x01,
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => scanner.ForwardOpenAsync(cfg));
        Assert.Contains("truncated", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ArgumentOutOfRange", ex.GetType().FullName!);

        await scanner.DisposeAsync();
    }

    /// <summary>
    /// Tiny TCP server that pretends to be an EtherNet/IP target. Replies
    /// to <c>RegisterSession</c> with a valid 4-byte protocol payload, and
    /// to the next <c>SendRRData</c> with a Forward_Open success MR reply
    /// carrying <paramref name="replyPayloadBytes"/> of payload — too few
    /// for the two UINT32 connection IDs the scanner expects.
    /// </summary>
    private sealed class HostileTargetServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly int _replyPayloadBytes;
        public int Port { get; }

        public HostileTargetServer(int replyPayloadBytes)
        {
            _replyPayloadBytes = replyPayloadBytes;
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        }

        public void Start()
        {
            _ = Task.Run(() => ServeAsync(_cts.Token));
        }

        private async Task ServeAsync(CancellationToken ct)
        {
            using var client = await _listener.AcceptTcpClientAsync(ct);
            using var stream = client.GetStream();

            // --- RegisterSession ---
            await HandleRegisterSessionAsync(stream, ct);

            // --- SendRRData with Forward_Open ---
            await HandleSendRRDataAsync(stream, ct);
        }

        private static async Task HandleRegisterSessionAsync(NetworkStream stream, CancellationToken ct)
        {
            var hdrBuf = new byte[EncapsulationHeader.Size];
            await ReadExactAsync(stream, hdrBuf, ct);
            var hdr = EncapsulationHeader.Parse(hdrBuf);

            var reqPayload = new byte[hdr.Length];
            await ReadExactAsync(stream, reqPayload, ct);

            // Reply with the same context, assign a session handle.
            var reply = new EncapsulationHeader
            {
                Command = EncapsulationCommand.RegisterSession,
                Length = 4,
                SessionHandle = 0x12345678,
                SenderContext = hdr.SenderContext,
            };
            var replyBuf = new byte[EncapsulationHeader.Size + 4];
            reply.WriteTo(replyBuf);
            BinaryPrimitives.WriteUInt16LittleEndian(replyBuf.AsSpan(EncapsulationHeader.Size), 1);
            await stream.WriteAsync(replyBuf, ct);
        }

        private async Task HandleSendRRDataAsync(NetworkStream stream, CancellationToken ct)
        {
            var hdrBuf = new byte[EncapsulationHeader.Size];
            await ReadExactAsync(stream, hdrBuf, ct);
            var hdr = EncapsulationHeader.Parse(hdrBuf);

            var reqPayload = new byte[hdr.Length];
            await ReadExactAsync(stream, reqPayload, ct);

            // Build a Forward_Open success MR reply with a short payload:
            //   service=0xD4 reserved=0 generalStatus=0 addStatusSize=0 + <N>B
            var mrReply = new byte[4 + _replyPayloadBytes];
            mrReply[0] = 0xD4; // 0x54 | 0x80
            mrReply[1] = 0x00;
            mrReply[2] = 0x00;
            mrReply[3] = 0x00;
            // (payload stays zero-filled)

            // Wrap in CPF: Null Address + Unconnected Data
            var cpfBuf = new byte[256];
            int cpfLen = CpfParser.Write(cpfBuf, new[]
            {
                new CpfItem { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
                new CpfItem { TypeId = CpfItemType.UnconnectedData, Data = mrReply },
            });

            // SendRRData payload: iface(4) + timeout(2) + CPF
            var payload = new byte[6 + cpfLen];
            cpfBuf.AsSpan(0, cpfLen).CopyTo(payload.AsSpan(6));

            var reply = new EncapsulationHeader
            {
                Command = EncapsulationCommand.SendRRData,
                Length = (ushort)payload.Length,
                SessionHandle = hdr.SessionHandle,
                SenderContext = hdr.SenderContext,
            };
            var replyBuf = new byte[EncapsulationHeader.Size + payload.Length];
            reply.WriteTo(replyBuf);
            payload.CopyTo(replyBuf.AsSpan(EncapsulationHeader.Size));
            await stream.WriteAsync(replyBuf, ct);
        }

        private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
        {
            int total = 0;
            while (total < buffer.Length)
            {
                int n = await stream.ReadAsync(buffer.AsMemory(total), ct);
                if (n == 0) throw new IOException("Connection closed early");
                total += n;
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            _cts.Dispose();
        }
    }
}
