// ============================================================================
// SampleStandardScanner — Non-Safety EtherNet/IP Scanner (Originator)
// ============================================================================
//
// What this sample does:
//   Acts as a Class 1 I/O scanner (originator). Opens a cyclic I/O connection
//   to an EtherNet/IP adapter (target), then continuously sends O→T data and
//   receives T→O data at the configured RPI. Prints a heartbeat showing what
//   it's sending and receiving.
//
//   Defaults match the StandardAdapterSample so you can run scanner + adapter
//   together for a self-contained end-to-end test:
//     Terminal 1:  dotnet run --project samples/StandardAdapterSample
//     Terminal 2:  dotnet run --project samples/SampleStandardScanner -- --target=127.0.0.1
//
// Default I/O configuration (matches StandardAdapterSample):
//   - O→T (we send): Assembly 102, 496 bytes
//   - T→O (we recv): Assembly 100, 500 bytes
//   - Config:        Assembly 105, 0 bytes (data-only config, no transfer)
//   - RPI: 10000us (10ms)
//
// Typical usage:
//   dotnet run --project samples/SampleStandardScanner -- --target=192.168.1.84
//   dotnet run --project samples/SampleStandardScanner -- --target=10.0.0.5 --rpi=20000
//
// CLI options:
//   --target=<ip>            Target adapter IP. Default: 127.0.0.1
//   --port=<n>               Target TCP port. Default: 44818
//   --asm-consumed=<n>       O→T target assembly (target's input). Default: 102
//   --asm-produced=<n>       T→O target assembly (target's output). Default: 100
//   --asm-config=<n>         Configuration assembly. Default: 105
//   --consumed-bytes=<n>     O→T data size in bytes. Default: 496
//   --produced-bytes=<n>     T→O data size in bytes. Default: 500
//   --rpi=<us>               Requested Packet Interval in microseconds. Default: 10000
//   --duration=<sec>         How long to run (0 = forever). Default: 0
//   --orig-vendor=<n>        Originator vendor ID. Default: 0x1234
//   --orig-serial=<hex>      Originator serial number. Default: 0xC0FFEE99
// ============================================================================

using System.Buffers.Binary;
using System.Net;
using EthernetIPSharp.Protocol;

string GetArg(string key, string defaultValue)
{
    var match = args.FirstOrDefault(a => a.StartsWith($"--{key}=", StringComparison.OrdinalIgnoreCase));
    return match is null ? defaultValue : match[(match.IndexOf('=') + 1)..];
}

static uint ParseHexOrDec(string s)
{
    s = s.Trim();
    if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        return Convert.ToUInt32(s.Substring(2), 16);
    return uint.Parse(s);
}

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------
string target           = GetArg("target", "127.0.0.1");
int    port             = int.Parse(GetArg("port", "44818"));
uint   asmConsumed      = uint.Parse(GetArg("asm-consumed", "102"));
uint   asmProduced      = uint.Parse(GetArg("asm-produced", "100"));
uint   asmConfig        = uint.Parse(GetArg("asm-config", "105"));
ushort consumedBytes    = ushort.Parse(GetArg("consumed-bytes", "496"));
ushort producedBytes    = ushort.Parse(GetArg("produced-bytes", "500"));
uint   rpiUs            = uint.Parse(GetArg("rpi", "10000"));
int    durationSec      = int.Parse(GetArg("duration", "0"));
ushort origVendor       = ushort.Parse(GetArg("orig-vendor", "4660"));        // 0x1234
uint   origSerial       = ParseHexOrDec(GetArg("orig-serial", "0xC0FFEE99"));

Console.WriteLine($"=== EthernetIPSharp Standard Scanner ===");
Console.WriteLine($"Target:        {target}:{port}");
Console.WriteLine($"Assemblies:    O->T={asmConsumed} ({consumedBytes}B), T->O={asmProduced} ({producedBytes}B), Config={asmConfig}");
Console.WriteLine($"RPI:           {rpiUs}us ({rpiUs / 1000.0}ms)");
Console.WriteLine($"Originator:    Vendor=0x{origVendor:X4}, Serial=0x{origSerial:X8}");
Console.WriteLine($"Duration:      {(durationSec == 0 ? "forever" : $"{durationSec}s")}");
Console.WriteLine();

// ----------------------------------------------------------------------------
// Connect: open TCP session, then RegisterSession
// ----------------------------------------------------------------------------
await using var scanner = new EipScanner();
Console.Write($"Connecting to {target}:{port}... ");
await scanner.ConnectAsync(IPAddress.Parse(target), port);
Console.WriteLine($"OK  (session=0x{scanner.SessionHandle:X8})");

// UDP transport for Class 1 I/O frames (CIP IO is over UDP port 2222)
var udp = new EipUdpTransport(new IPEndPoint(IPAddress.Any, 2222));
await udp.StartAsync(CancellationToken.None);

// ----------------------------------------------------------------------------
// Open the I/O connection via ForwardOpen
// ----------------------------------------------------------------------------
var config = new ForwardOpenConfig
{
    ConsumedAssembly  = asmConsumed,    // target's input  (we send to it)
    ProducedAssembly  = asmProduced,    // target's output (target sends to us)
    ConfigAssembly    = asmConfig,
    ConsumedSize      = consumedBytes,
    ProducedSize      = producedBytes,
    Rpi               = rpiUs,
    TransportClass    = 1,              // Class 1 cyclic implicit I/O
    TimeoutMultiplier = 2,              // x16
};

Console.Write("Opening Forward Open... ");
ScannerConnection conn;
try
{
    conn = await scanner.ForwardOpenAsync(config);
}
catch (Exception ex)
{
    Console.WriteLine($"FAILED: {ex.Message}");
    return;
}
Console.WriteLine("OK");
Console.WriteLine();

// ----------------------------------------------------------------------------
// Pre-fill our O→T data with a known pattern so the adapter sees recognizable
// bytes. DINT[0] gets incremented each tick to act as a heartbeat.
// ----------------------------------------------------------------------------
for (int i = 0; i < consumedBytes / 4; i++)
    conn.Write(i * 4, -(i + 1));   // -1, -2, -3, ... so it differs from the adapter's pre-filled ramp

// ----------------------------------------------------------------------------
// Print the first incoming packet, then every ~5 seconds afterwards.
// ----------------------------------------------------------------------------
int rxPackets = 0;
DateTime lastRxLog = DateTime.MinValue;
conn.DataReceived += data =>
{
    rxPackets++;
    var now = DateTime.UtcNow;
    if (rxPackets == 1 || (now - lastRxLog).TotalSeconds >= 5)
    {
        var bytes = data.ToArray();
        int dint0 = bytes.Length >= 4  ? BinaryPrimitives.ReadInt32LittleEndian(bytes)             : 0;
        int dint1 = bytes.Length >= 8  ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4))   : 0;
        int dint2 = bytes.Length >= 12 ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8))   : 0;
        Log($"[T->O DATA] Packet #{rxPackets} ({data.Length} bytes) DINT[0]={dint0}, [1]={dint1}, [2]={dint2}");
        lastRxLog = now;
    }
};

// ----------------------------------------------------------------------------
// Heartbeat loop: bump our O→T DINT[0] every 200ms and print stats
// ----------------------------------------------------------------------------
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
if (durationSec > 0)
    cts.CancelAfter(TimeSpan.FromSeconds(durationSec));

Log("Running. Press Ctrl+C to stop.");
Log("");

int tick = 0;
try
{
    while (!cts.Token.IsCancellationRequested)
    {
        await Task.Delay(200, cts.Token);
        tick++;
        conn.Write(0, tick);

        int recvDint0 = conn.Read<int>(0);
        Console.Write($"\r[{DateTime.Now:HH:mm:ss.fff}] Sent[0]={tick,10}  |  Recv[0]={recvDint0,10}  |  TX={conn.SendCount}  RX={conn.ReceiveCount}    ");
        if (tick % 25 == 0) Console.WriteLine();
    }
}
catch (OperationCanceledException) { }

Console.WriteLine();
Log($"[SHUTDOWN] Closing connection (TX={conn.SendCount}, RX={conn.ReceiveCount})");
try { await conn.CloseAsync(); } catch (Exception ex) { Log($"  Close failed: {ex.Message}"); }
await udp.DisposeAsync();
Log("Done.");

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
static void Log(string message) =>
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {message}");
