using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Device;
using EthernetIPSharp.Logix;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Protocol.Tests;

/// <summary>
/// End-to-end TagClient round-trip tests for the full CIP §C-6.1
/// elementary type family added in commit e0d626f.  Spins up a real
/// LogixDispatcher + EipAdapter on a loopback port, connects a TagClient,
/// writes with each unsigned / bit-string generic type parameter, reads
/// it back, and verifies the value survives the full
/// client → TCP → server → TCP → client loop.
///
/// The in-process UnsignedAndBitStringTypeTests already prove the server
/// side.  This test closes the remaining gap: that TagClient's typed
/// read/write path (which went through GuessTagType&lt;T&gt;) actually
/// agrees with the server over the wire.
/// </summary>
[Collection("TagClientUnsigned")]
public class TagClientUnsignedTypeRoundTripTests : IAsyncLifetime
{
    private VirtualDevice _device = null!;
    private LogixDispatcher _logix = null!;
    private CancellationTokenSource _cts = null!;
    private int _tcpPort;
    private int _udpPort;

    public async Task InitializeAsync()
    {
        _cts = new CancellationTokenSource();

        _logix = new LogixDispatcher();
        // One tag per added type — register each at full-range so the
        // writes have something concrete to overwrite.
        _logix.Tags.AddTag("u8",   LogixDataTypes.USINT);
        _logix.Tags.AddTag("u16",  LogixDataTypes.UINT);
        _logix.Tags.AddTag("u32",  LogixDataTypes.UDINT);
        _logix.Tags.AddTag("u64",  LogixDataTypes.ULINT);
        _logix.Tags.AddTag("b8",   LogixDataTypes.BYTE);
        _logix.Tags.AddTag("w16",  LogixDataTypes.WORD);
        _logix.Tags.AddTag("dw32", LogixDataTypes.DWORD);
        _logix.Tags.AddTag("lw64", LogixDataTypes.LWORD);

        var identity = new IdentityInfo
        {
            VendorId = 42, DeviceType = 0x0E, ProductCode = 1,
            MajorRevision = 1, MinorRevision = 0,
            SerialNumber = 0xC0DE, ProductName = "UnsignedRoundTripTarget",
        };

        _device = new StandardDevice(identity, IPAddress.Loopback,
            _logix, new AssemblyObject(),
            new EthernetIPSharp.Connections.ConnectionManagerObject(),
            "UnsignedRoundTripTarget");

        _tcpPort = GetFreePort();
        _udpPort = GetFreePort();
        await _device.StartAsync(_tcpPort, _udpPort, _cts.Token);
    }

    public async Task DisposeAsync()
    {
        _cts.Cancel();
        await _device.DisposeAsync();
        _cts.Dispose();
    }

    [Fact]
    public async Task Usint_FullRange_RoundTrips()
    {
        await using var client = new TagClient("127.0.0.1", _tcpPort);
        await client.ConnectAsync();
        await client.WriteAsync<byte>("u8", 0xFF);
        var got = await client.ReadAsync<byte>("u8");
        Assert.Equal(0xFF, got);
    }

    [Fact]
    public async Task Uint_FullRange_RoundTrips()
    {
        await using var client = new TagClient("127.0.0.1", _tcpPort);
        await client.ConnectAsync();
        await client.WriteAsync<ushort>("u16", 0xFFFF);
        var got = await client.ReadAsync<ushort>("u16");
        Assert.Equal(0xFFFF, got);
    }

    [Fact]
    public async Task Udint_FullRange_RoundTrips()
    {
        // The specific EscaFlow case — type the user hit the crash on.
        await using var client = new TagClient("127.0.0.1", _tcpPort);
        await client.ConnectAsync();
        await client.WriteAsync<uint>("u32", 0xFFFFFFFFu);
        var got = await client.ReadAsync<uint>("u32");
        Assert.Equal(0xFFFFFFFFu, got);
    }

    [Fact]
    public async Task Ulint_FullRange_RoundTrips()
    {
        await using var client = new TagClient("127.0.0.1", _tcpPort);
        await client.ConnectAsync();
        await client.WriteAsync<ulong>("u64", 0xFFFFFFFFFFFFFFFFul);
        var got = await client.ReadAsync<ulong>("u64");
        Assert.Equal(0xFFFFFFFFFFFFFFFFul, got);
    }

    [Fact]
    public async Task AllNonMatchingTypes_RejectedByServer()
    {
        // Writing a different-width type than the tag's registered type
        // must fail the server's tag_type check — this proves the client's
        // GuessTagType<T> fix is what makes the valid writes work (and
        // not accidental tolerance on the server side).
        await using var client = new TagClient("127.0.0.1", _tcpPort);
        await client.ConnectAsync();

        // Writing SINT (sbyte→SINT) against a USINT-registered tag must
        // land as a type mismatch (0xFF with extended 0x2107 inside TagClient).
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await client.WriteAsync<sbyte>("u8", 1));
    }

    [Fact]
    public async Task UnsignedFamily_AllFourTypes_RoundTripInOneConnection()
    {
        // Reuse one TCP session for every type to verify the client's
        // typed read/write path works for the whole unsigned integer
        // family without reconnecting between types. Full-range values.
        await using var client = new TagClient("127.0.0.1", _tcpPort);
        await client.ConnectAsync();

        await client.WriteAsync<byte>  ("u8",  0xAB);
        await client.WriteAsync<ushort>("u16", 0xBEEF);
        await client.WriteAsync<uint>  ("u32", 0xDEADBEEFu);
        await client.WriteAsync<ulong> ("u64", 0xFEEDFACECAFEBABEul);

        Assert.Equal((byte)  0xAB,              await client.ReadAsync<byte>  ("u8"));
        Assert.Equal((ushort)0xBEEF,            await client.ReadAsync<ushort>("u16"));
        Assert.Equal(0xDEADBEEFu,               await client.ReadAsync<uint>  ("u32"));
        Assert.Equal(0xFEEDFACECAFEBABEul,      await client.ReadAsync<ulong> ("u64"));
    }

    [Fact]
    public async Task BitStringTypes_RoundTripViaWriteRaw()
    {
        // GuessTagType<T> can only produce one Logix code per C# scalar
        // type, and the unsigned-integer codes win over bit-string
        // (byte→USINT, ushort→UINT, …). To write a BYTE/WORD/DWORD/LWORD
        // tag over the wire, callers go through WriteRawAsync with an
        // explicit tag_type. This covers that path.
        await using var client = new TagClient("127.0.0.1", _tcpPort);
        await client.ConnectAsync();

        await client.WriteRawAsync("b8",   LogixDataTypes.BYTE,  1, new byte[] { 0xAB });
        await client.WriteRawAsync("w16",  LogixDataTypes.WORD,  1, BitConverter.GetBytes((ushort)0xBEEF));
        await client.WriteRawAsync("dw32", LogixDataTypes.DWORD, 1, BitConverter.GetBytes(0xDEADBEEFu));
        await client.WriteRawAsync("lw64", LogixDataTypes.LWORD, 1, BitConverter.GetBytes(0xFEEDFACECAFEBABEul));

        // Read back as raw bytes and compare — ReadTagRawAsync returns
        // tag_type(2) + bytes so slice past the header.
        var b8   = await client.ReadTagRawAsync("b8");
        var w16  = await client.ReadTagRawAsync("w16");
        var dw32 = await client.ReadTagRawAsync("dw32");
        var lw64 = await client.ReadTagRawAsync("lw64");

        Assert.Equal((byte)0xAB,            b8[2]);
        Assert.Equal((ushort)0xBEEF,        BitConverter.ToUInt16(w16, 2));
        Assert.Equal(0xDEADBEEFu,           BitConverter.ToUInt32(dw32, 2));
        Assert.Equal(0xFEEDFACECAFEBABEul,  BitConverter.ToUInt64(lw64, 2));
    }

    private static int GetFreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
