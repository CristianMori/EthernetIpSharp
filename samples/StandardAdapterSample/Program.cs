// ============================================================================
// StandardAdapterSample — Non-Safety EtherNet/IP Adapter (Target)
// ============================================================================
//
// What this sample does:
//   Acts as a plain (non-safety) EtherNet/IP I/O adapter. Compatible with the
//   stock Studio 5000 "Generic Ethernet Module" configuration. Useful for
//   echoing data from a PLC, or as a starting point for a real adapter.
//
// Default configuration matches:
//   Studio 5000 Generic Ethernet Module
//   - Comm Format: Data - DINT
//   - Input  Assembly Instance: 100   Size: 125 DINT (500 bytes)
//   - Output Assembly Instance: 102   Size: 124 DINT (496 bytes)
//   - Config Assembly Instance: 105   Size: 10 bytes
//
// Typical usage:
//   dotnet run --project samples/StandardAdapterSample
//   dotnet run --project samples/StandardAdapterSample -- --bind=192.168.1.84
//   dotnet run --project samples/StandardAdapterSample -- --asm-input=100 --input-bytes=500
//
// CLI options:
//   --bind=<ip>             Local IP to bind on. Default: 0.0.0.0 (all NICs)
//   --vendor=<n>            Vendor ID. Default: 1 (Rockwell)
//   --device-type=<n>       Device type. Default: 0x0C (Communications Adapter)
//   --product-code=<n>      Product code. Default: 1
//   --serial=<hex>          Device serial number. Default: 0xC0FFEE42
//   --product=<text>        Product name. Default: "EthernetIPSharp Echo Module"
//   --asm-input=<n>         Input (T->O) assembly instance. Default: 100
//   --asm-output=<n>        Output (O->T) assembly instance. Default: 102
//   --asm-config=<n>        Configuration assembly instance. Default: 105
//   --input-bytes=<n>       Input assembly size in bytes. Default: 500
//   --output-bytes=<n>      Output assembly size in bytes. Default: 496
//   --config-bytes=<n>      Config assembly size in bytes. Default: 10
//   --tick-ms=<n>           Update period for our produced data. Default: 200
// ============================================================================

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;
using EthernetIPSharp.Device;
using EthernetIPSharp.Protocol;

// ----------------------------------------------------------------------------
// Minimal --key=value argument parser
// ----------------------------------------------------------------------------
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
// Configuration (all overridable via CLI)
// ----------------------------------------------------------------------------
IPAddress bindAddress      = IPAddress.Parse(GetArg("bind", "0.0.0.0"));
ushort   vendorId          = ushort.Parse(GetArg("vendor", "1"));
ushort   deviceType        = ushort.Parse(GetArg("device-type", "12"));        // 0x000C = Comms Adapter
ushort   productCode       = ushort.Parse(GetArg("product-code", "1"));
uint     serialNumber      = ParseHexOrDec(GetArg("serial", "0xC0FFEE42"));
string   productName       = GetArg("product", "EthernetIPSharp Echo Module");
uint     asmInput          = uint.Parse(GetArg("asm-input", "100"));           // T->O (we produce, PLC consumes)
uint     asmOutput         = uint.Parse(GetArg("asm-output", "102"));          // O->T (PLC produces, we consume)
uint     asmConfig         = uint.Parse(GetArg("asm-config", "105"));
int      inputBytes        = int.Parse(GetArg("input-bytes", "500"));
int      outputBytes       = int.Parse(GetArg("output-bytes", "496"));
int      configBytes       = int.Parse(GetArg("config-bytes", "10"));
int      tickMs            = int.Parse(GetArg("tick-ms", "200"));

// ----------------------------------------------------------------------------
// Build identity (what scanners see in ListIdentity / Identity object)
// ----------------------------------------------------------------------------
var identity = new IdentityInfo
{
    VendorId      = vendorId,
    DeviceType    = deviceType,
    ProductCode   = productCode,
    MajorRevision = 1,
    MinorRevision = 0,
    SerialNumber  = serialNumber,
    ProductName   = productName,
    Status        = 0x0000,
};

Log("=== EthernetIPSharp Echo Module ===");
Log($"Bind address: {bindAddress}");
Log($"TCP port:     {EipAdapter.DefaultPort}");
Log($"UDP port:     {EipUdpTransport.IoPort}");
Log($"Identity: Vendor=0x{vendorId:X4} DeviceType=0x{deviceType:X4} Product=0x{productCode:X4} Serial=0x{serialNumber:X8}");
Log("");

await using var device = new StandardDevice(identity, bindAddress, "test");

// ----------------------------------------------------------------------------
// Assembly registration. Pre-fill the input assembly with a known ramp pattern
// so a connected PLC immediately sees recognizable, non-zero data.
// ----------------------------------------------------------------------------
var produced = device.AddAssembly(asmInput,  inputBytes,  $"T->O Input ({inputBytes / 4} DINTs)");
var consumed = device.AddAssembly(asmOutput, outputBytes, $"O->T Output ({outputBytes / 4} DINTs)");
var config   = device.AddAssembly(asmConfig, configBytes, "Configuration");

int dintCount = inputBytes / 4;
for (int i = 0; i < dintCount; i++)
    produced.Write(i * 4, i + 1);

Log("Assemblies configured:");
Log($"  Instance {asmInput,3}: T->O  {inputBytes,4} bytes ({dintCount} DINTs) - pre-filled with ramp 1..{dintCount}");
Log($"  Instance {asmOutput,3}: O->T  {outputBytes,4} bytes ({outputBytes / 4} DINTs) - waiting for PLC writes");
Log($"  Instance {asmConfig,3}: Config  {configBytes,2} bytes");
Log("");

// ----------------------------------------------------------------------------
// Connection lifecycle logging
// ----------------------------------------------------------------------------
int connectionCount = 0;

device.ConnectionManager.ConnectionEstablished += conn =>
{
    connectionCount++;
    Log($"[CONN OPEN] #{connectionCount}");
    Log($"  Serial:         {conn.ConnectionSerialNumber}");
    Log($"  Originator:     Vendor=0x{conn.OriginatorVendorId:X4}, Serial=0x{conn.OriginatorSerialNumber:X8}");
    Log($"  O->T:           Assembly {conn.ConsumedAssemblyInstance}, {conn.OtoTSize} bytes, RPI={conn.OtoTRpi / 1000.0}ms");
    Log($"  T->O:           Assembly {conn.ProducedAssemblyInstance}, {conn.TtoOSize} bytes, RPI={conn.TtoORpi / 1000.0}ms");
    Log($"  Transport:      Class {(int)conn.TransportClass}");
    Log($"  Timeout:        x{GetMultiplier(conn.TimeoutMultiplier)} ({conn.ConnectionTimeout.TotalMilliseconds}ms)");
    Log($"  Connection IDs: O->T=0x{conn.OtoTConnectionId:X8}, T->O=0x{conn.TtoOConnectionId:X8}");
    Log($"  RemoteEndpoint: {conn.RemoteEndpoint?.ToString() ?? "NULL"}");
};

device.ConnectionManager.ConnectionRemoved += conn =>
{
    Log($"[CONN CLOSED] Serial={conn.ConnectionSerialNumber}, State={conn.State}");
    if (conn.State == ConnectionState.TimedOut)
        Log("  (timed out - PLC stopped sending)");
};

// ----------------------------------------------------------------------------
// Sample the inbound (O->T) data. Logged once on first packet, then every 5
// seconds, so the console doesn't flood at fast RPIs.
// ----------------------------------------------------------------------------
int otPacketCount = 0;
DateTime lastOtLog = DateTime.MinValue;

consumed.DataChanged += (instanceId, data) =>
{
    otPacketCount++;
    var now = DateTime.UtcNow;

    if (otPacketCount == 1 || (now - lastOtLog).TotalSeconds >= 5)
    {
        var bytes = data.ToArray();
        int dint0 = BinaryPrimitives.ReadInt32LittleEndian(bytes);
        int dint1 = bytes.Length >= 8  ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4))  : 0;
        int dint2 = bytes.Length >= 12 ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8))  : 0;

        Log($"[O->T DATA] Packet #{otPacketCount} ({data.Length} bytes)");
        Log($"  DINT[0]={dint0}, DINT[1]={dint1}, DINT[2]={dint2} ...");

        lastOtLog = now;
    }
};

// ----------------------------------------------------------------------------
// Start the adapter
// ----------------------------------------------------------------------------
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Log("[SHUTDOWN] Ctrl+C received, stopping...");
    cts.Cancel();
};

try
{
    await device.StartAsync(cts.Token);
}
catch (SocketException ex)
{
    Log($"[ERROR] Cannot bind to {bindAddress}: {ex.Message}");
    Log("  Make sure this IP is assigned to a local network adapter.");
    Log($"  e.g.: netsh interface ip add address \"Ethernet\" {bindAddress} 255.255.255.0");
    return;
}

Log("");
Log("Registered CIP objects:");
foreach (var cls in device.Dispatcher.RegisteredClasses)
    Log($"  0x{cls.Key:X04} - {cls.Value.Name}");

Log("");
Log("Ready. Waiting for PLC connection...");
Log("  - PLC connects via TCP 44818 and sends Forward Open");
Log("  - Works with real PLCs and Logix emulators");
Log("  - Press Ctrl+C to stop");
Log("");

// ----------------------------------------------------------------------------
// Main loop: bump DINT[0] of the produced assembly each tick so the PLC sees
// a steadily incrementing counter — a quick visual liveness indicator.
// ----------------------------------------------------------------------------
int tick = 0;
try
{
    while (!cts.Token.IsCancellationRequested)
    {
        await Task.Delay(tickMs, cts.Token);
        tick++;

        int out0   = consumed.Read<int>(0);
        int out45  = consumed.Read<int>(45 * 4);
        int out120 = consumed.Read<int>(120 * 4);
        // Config assembly is 10 bytes — byte 5 is what the PLC's Generic
        // Ethernet Module pushed at Forward Open (Simple Data Segment 0x80).
        byte cfg5  = config.DataSize >= 6 ? config.GetData()[5] : (byte)0;
        produced.Write(0, tick);

        int activeConns = device.ConnectionManager.ActiveConnections.Count;
        Console.Write($"\r[{DateTime.Now:HH:mm:ss.fff}] Out[0]={out0,10} Out[45]={out45,10} Out[120]={out120,10}  Cfg[5]=0x{cfg5:X2}  In[0]={tick,10}  Conns={activeConns}  O->T rx={otPacketCount}  T->O tx={device.TtoOSendCount}    ");

        if (tick % 25 == 0)
            Console.WriteLine();
    }
}
catch (OperationCanceledException) { }

Log($"[SHUTDOWN] Total O->T packets received: {otPacketCount}");
Log("[SHUTDOWN] Done.");

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
static void Log(string message) =>
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {message}");

// ConnectionTimeoutMultiplier encoding: 0=*4 .. 7=*512
static int GetMultiplier(byte value) => value switch
{
    0 => 4, 1 => 8, 2 => 16, 3 => 32, 4 => 64, 5 => 128, 6 => 256, 7 => 512, _ => 4,
};
