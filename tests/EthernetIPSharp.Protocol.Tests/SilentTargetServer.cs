using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Protocol.Tests;

/// <summary>
/// Loopback EtherNet/IP target that answers RegisterSession (unless told not
/// to) and a configurable number of SendRRData requests with a generic
/// Forward_Open-style success reply, then reads and ignores everything else.
/// Used to prove client request timeouts: the reply never arrives.
/// </summary>
internal sealed class SilentTargetServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly bool _answerRegister;
    private int _rrReplies;
    public int Port { get; }

    public SilentTargetServer(int rrReplies = 0, bool answerRegister = true)
    {
        _rrReplies = rrReplies;
        _answerRegister = answerRegister;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = Task.Run(() => ServeAsync(_cts.Token));
    }

    private async Task ServeAsync(CancellationToken ct)
    {
        try
        {
            using var client = await _listener.AcceptTcpClientAsync(ct);
            using var stream = client.GetStream();
            while (!ct.IsCancellationRequested)
            {
                var hdrBuf = new byte[EncapsulationHeader.Size];
                await ReadExactAsync(stream, hdrBuf, ct);
                var hdr = EncapsulationHeader.Parse(hdrBuf);
                var req = new byte[hdr.Length];
                await ReadExactAsync(stream, req, ct);

                if (hdr.Command == EncapsulationCommand.RegisterSession && _answerRegister)
                {
                    var payload = new byte[4];
                    BinaryPrimitives.WriteUInt16LittleEndian(payload, 1);
                    await Reply(stream, hdr, 0x12345678, payload, ct);
                }
                else if (hdr.Command == EncapsulationCommand.SendRRData && _rrReplies > 0)
                {
                    _rrReplies--;
                    // Forward_Open success reply: 0xD4, reserved, status 0, no extra status, 26 data bytes.
                    var mr = new byte[4 + 26];
                    mr[0] = 0xD4;
                    var cpf = new byte[256];
                    int n = CpfParser.Write(cpf, new[]
                    {
                        new CpfItem { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
                        new CpfItem { TypeId = CpfItemType.UnconnectedData, Data = mr },
                    });
                    var payload = new byte[6 + n];
                    cpf.AsSpan(0, n).CopyTo(payload.AsSpan(6));
                    await Reply(stream, hdr, hdr.SessionHandle, payload, ct);
                }
                // anything else: silence
            }
        }
        catch { /* test server: connection closed or disposed */ }
    }

    private static async Task Reply(NetworkStream s, EncapsulationHeader req, uint session, byte[] payload, CancellationToken ct)
    {
        var h = new EncapsulationHeader
        {
            Command = req.Command,
            Length = (ushort)payload.Length,
            SessionHandle = session,
            SenderContext = req.SenderContext,
        };
        var buf = new byte[EncapsulationHeader.Size + payload.Length];
        h.WriteTo(buf);
        payload.CopyTo(buf.AsSpan(EncapsulationHeader.Size));
        await s.WriteAsync(buf, ct);
    }

    private static async Task ReadExactAsync(NetworkStream s, byte[] b, CancellationToken ct)
    {
        int t = 0;
        while (t < b.Length)
        {
            int n = await s.ReadAsync(b.AsMemory(t), ct);
            if (n == 0) throw new IOException("closed");
            t += n;
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
    }
}
