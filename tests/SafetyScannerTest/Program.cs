using System.Net;
using EthernetIPSharp.Protocol;
using EthernetIPSharp.Safety;

// Target: 1734-ENT adapter with safety modules
string targetIp = args.Length > 0 ? args[0] : "192.168.1.76";
byte backplaneSlot = args.Length > 1 ? byte.Parse(args[1]) : (byte)1;
var format = SafetyFormat.Extended;

Console.WriteLine($"=== CIP Safety Scanner → 1734 ===");
Console.WriteLine($"Target: {targetIp}, Backplane Slot: {backplaneSlot}");
Console.WriteLine();

// --- Spoof PLC identity (from capture) ---
ushort origVendor = 0x0001;  // Rockwell
uint origSerial = 0x012FE10E;

// Originator UNID (PLC's identity)
// SNN: 2026-05-10 03:16:41.289 UTC → bytes C9 12 B4 00 8D 4D
var ourSnn = new SafetyNetworkNumber(new byte[] { 0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D });
var ourOunid = new UniqueNetworkId { Snn = ourSnn, NodeAddress = 0xC0A80160 }; // 192.168.1.96

// Target UNID (module at slot 1)
// SNN: 2026-05-11 04:18:55.544 UTC → bytes B8 0D ED 00 8E 4D
var targetSnn = new SafetyNetworkNumber(new byte[] { 0xB8, 0x0D, 0xED, 0x00, 0x8E, 0x4D });
var targetTunid = new UniqueNetworkId { Snn = targetSnn, NodeAddress = 0x00000001 };

// SCID from capture
// SCTS: 2026-05-11 04:18:55.542 UTC → bytes B6 0D ED 00 8E 4D
var scid = new SafetyConfigurationId
{
    Sccrc = 0x781B988E,
    Scts = new SafetyNetworkNumber(new byte[] { 0xB6, 0x0D, 0xED, 0x00, 0x8E, 0x4D }),
};

// --- Route: backplane port 1, link address = slot ---
var routePrefix = new byte[] { 0x01, backplaneSlot };

// --- Electronic key for 1734-IB8S (slot 1 safety input) ---
// 0x34 format4: vendor(2) devType(2) prodCode(2) compat+major(1) minor(1) = 10 bytes
var electronicKey = new byte[]
{
    0x34, 0x04,                 // Electronic key, format 4
    0x01, 0x00,                 // Vendor: 0x0001 (Rockwell)
    0x23, 0x00,                 // Device Type: 0x0023 (Safety Discrete I/O)
    0x10, 0x00,                 // Product Code: 0x0010
    0x82,                       // Compatibility bit set + Major Rev 2
    0x02,                       // Minor Rev 2
};

// --- Assembly path helpers ---
// Encode class 0x04 + instance (8-bit or 16-bit as needed)
static byte[] AssemblyInstance(uint instance)
{
    if (instance <= 0xFF)
        return new byte[] { 0x20, 0x04, 0x24, (byte)instance };
    else
        return new byte[] { 0x20, 0x04, 0x25, 0x00, (byte)(instance & 0xFF), (byte)(instance >> 8) };
}

// Server app path: ekey + [class 0x04, config] + [class 0x04, consumed] + [class 0x04, produced]
// Server: config=0x0360, OT_consumed=0x0234, TO_produced=0xC7
var serverAppPath = Concat(electronicKey,
    AssemblyInstance(0x0360),
    AssemblyInstance(0x0234),
    AssemblyInstance(0xC7));

// Client app path: ekey + [class 0x04, config] + [class 0x04, consumed] + [class 0x04, produced]
// Client: config=0x0360, OT_consumed=0xC7, TO_produced=0x0244
var clientAppPath = Concat(electronicKey,
    AssemblyInstance(0x0360),
    AssemblyInstance(0xC7),
    AssemblyInstance(0x0244));

Console.WriteLine($"Server path ({serverAppPath.Length}B): {Hex(serverAppPath)}");
Console.WriteLine($"Client path ({clientAppPath.Length}B): {Hex(clientAppPath)}");
Console.WriteLine();

// --- Connection configs ---
// Server: we produce O→T (data), target sends T→O (TCOO)
var serverConfig = new SafetyForwardOpenConfig
{
    ConfigAssembly = 0x0360,
    ConsumedAssembly = 0x0234,
    ProducedAssembly = 0xC7,
    ConsumedDataSize = 1,       // 1 byte safety data
    ProducedDataSize = 1,
    OtoTRpi = 20_000,           // O→T: 20ms (data we send)
    TtoORpi = 380_000,          // T→O: 380ms (TCOO from target)
    OtoTConnectionSize = 7,     // WireSize(1, Extended) = 7
    TtoOConnectionSize = 6,     // TCOO = 6 bytes
    Format = format,
    Tunid = targetTunid,
    Ounid = ourOunid,
    Scid = scid,
    PingIntervalMultiplier = 19,
    TimeCoordMsgMinMultiplier = 0,
    NetworkTimeExpectationMultiplier = 625, // 80ms
    TimeoutMultiplier = 2,
    MaxFaultNumber = 2,
    InitialTimestamp = 0xFFFF,
    InitialRolloverValue = 0xFFFF,
    ConnectionTimeoutMultiplier = 1,    // *8
    PriorityTimeTick = 0x05,
    TimeoutTicks = 156,
};

// Client: target produces T→O (data), we send O→T (TCOO)
var clientConfig = new SafetyForwardOpenConfig
{
    ConfigAssembly = 0x0360,
    ConsumedAssembly = 0xC7,
    ProducedAssembly = 0x0244,
    ConsumedDataSize = 1,
    ProducedDataSize = 1,
    OtoTRpi = 1_000_000,        // O→T: 1000ms (TCOO we send)
    TtoORpi = 10_000,           // T→O: 10ms (data from target)
    OtoTConnectionSize = 6,     // TCOO = 6 bytes
    TtoOConnectionSize = 7,     // WireSize(1, Extended) = 7
    Format = format,
    Tunid = targetTunid,
    Ounid = ourOunid,
    Scid = scid,
    PingIntervalMultiplier = 100,
    TimeCoordMsgMinMultiplier = 0,
    NetworkTimeExpectationMultiplier = 313, // ~40ms
    TimeoutMultiplier = 2,
    MaxFaultNumber = 2,
    InitialTimestamp = 0xFFFF,  // Will be set by target in app reply
    InitialRolloverValue = 0xFFFF,
    ConnectionTimeoutMultiplier = 1,
    PriorityTimeTick = 0x05,
    TimeoutTicks = 156,
};

// --- Connect ---
var scanner = new EipScanner();
Console.Write($"Connecting to {targetIp}:44818...");
await scanner.ConnectAsync(IPAddress.Parse(targetIp));
Console.WriteLine(" OK");

// Start UDP transport
var udpEndpoint = new IPEndPoint(IPAddress.Any, 2222);
var udp = new EipUdpTransport(udpEndpoint);
await udp.StartAsync(CancellationToken.None);

try
{
    Console.WriteLine("Opening safety connection pair...");
    var conn = await SafetyScannerConnection.OpenAsync(
        scanner, udp, serverConfig, clientConfig, origVendor, origSerial,
        routePrefix, serverAppPath, clientAppPath);

    conn.Log += msg => Console.WriteLine($"[SAFETY] {msg}");
    conn.DataReceived += data =>
    {
        Console.WriteLine($"[DATA] Received: [{string.Join(" ", data.Span.ToArray().Select(b => b.ToString("X2")))}]");
    };

    // Set output data (1 byte, all zeros = safe state)
    conn.SetOutputData(new byte[] { 0x00 });

    Console.WriteLine("Running. Press Ctrl+C to stop.");
    Console.WriteLine();

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    try
    {
        while (!cts.Token.IsCancellationRequested)
            await Task.Delay(1000, cts.Token);
    }
    catch (OperationCanceledException) { }

    Console.WriteLine("\nClosing...");
    await conn.CloseAsync();
}
catch (Exception ex)
{
    Console.WriteLine($"ERROR: {ex.Message}\n{ex.StackTrace}");
}
finally
{
    await scanner.DisposeAsync();
    await udp.DisposeAsync();
}

Console.WriteLine("Done.");

// --- Helpers ---
static byte[] Concat(params byte[][] arrays)
{
    int total = arrays.Sum(a => a.Length);
    var result = new byte[total];
    int off = 0;
    foreach (var a in arrays) { a.CopyTo(result, off); off += a.Length; }
    return result;
}

static string Hex(byte[] data) => string.Join(" ", data.Select(b => b.ToString("X2")));
