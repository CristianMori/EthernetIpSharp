// ============================================================================
// SampleSafetyScanner — CIP Safety Originator (scanner side)
// ============================================================================
//
// What this sample does:
//   Acts as a CIP Safety ORIGINATOR (scanner). Opens a safety connection pair
//   to a real safety target — by default a 1734-IB8S safety input module behind
//   a 1734-ENT EtherNet/IP adapter. Sends Forward Open for both directions
//   (server: we produce O→T data, client: target produces T→O data), then
//   runs the time coordination handshake and streams data both ways.
//
// Target wiring (defaults):
//   1734-ENT adapter at 192.168.1.76, with a 1734-IB8S safety input module in
//   slot 1 of the backplane. The route prefix [0x01, slot] tells the ENT to
//   forward the message to that backplane slot.
//
// Typical usage:
//   dotnet run --project samples/SampleSafetyScanner
//   dotnet run --project samples/SampleSafetyScanner -- --target=192.168.1.76 --slot=1
//
// CLI options:
//   --target=<ip>             Target adapter IP. Default: 192.168.1.76
//   --slot=<n>                Backplane slot of the safety module. Default: 1
//   --orig-vendor=<n>         Originator vendor ID. Default: 1 (Rockwell)
//   --orig-serial=<hex>       Originator serial number. Default: 0x012FE10E
//   --our-snn=<hex_12>        Our (originator) Safety Network Number. Default: 4D8D_00B4_12C9
//   --our-node=<hex>          Our safety node address (IP packed BE). Default: 0xC0A80160 (192.168.1.96)
//   --target-snn=<hex_12>     Target SNN. Default: 4D8E_00ED_0DB8
//   --target-node=<hex>       Target safety node address. Default: 0x00000001
//   --sccrc=<hex>             Safety Configuration CRC. Default: 0x781B988E
//   --scts=<hex_12>           Safety Config Timestamp. Default: 4D8E_00ED_0DB6
//
// The safety identity values (SNN, SCCRC, SCTS, electronic key, assembly
// instances) below are typically copied from a working capture of the target
// being commissioned by a real PLC. They are device-specific.
// ============================================================================

using System.Net;
using EthernetIPSharp.Protocol;
using EthernetIPSharp.Safety;

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

// Parse "4D8D_00B4_12C9" → 6 bytes little-endian {C9, 12, B4, 00, 8D, 4D}
static byte[] ParseSnn(string s)
{
    var hex = s.Replace("_", "").Replace("-", "").Replace(" ", "");
    if (hex.Length != 12) throw new ArgumentException("SNN must be 12 hex chars (6 bytes)");
    var bytes = new byte[6];
    for (int i = 0; i < 6; i++)
        bytes[5 - i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
    return bytes;
}

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------
string targetIp     = GetArg("target", "192.168.1.76");
byte   backplaneSlot = byte.Parse(GetArg("slot", "1"));

// Originator (us) identity — must match how the safety target was commissioned
ushort origVendor   = ushort.Parse(GetArg("orig-vendor", "1"));
uint   origSerial   = ParseHexOrDec(GetArg("orig-serial", "0x012FE10E"));

// Originator UNID — our identity as a CIP Safety device
byte[] ourSnnBytes  = ParseSnn(GetArg("our-snn", "4D8D_00B4_12C9"));
uint   ourNode      = ParseHexOrDec(GetArg("our-node", "0xC0A80160"));     // 192.168.1.96

// Target UNID — identifies the specific safety module we're talking to
byte[] tgtSnnBytes  = ParseSnn(GetArg("target-snn", "4D8E_00ED_0DB8"));
uint   tgtNode      = ParseHexOrDec(GetArg("target-node", "0x00000001"));

// Safety Configuration Identifier — proves we have the SAME configuration the
// target was commissioned with. SCCRC = CRC over the config; SCTS = timestamp
// of when the config was downloaded.
uint   sccrc        = ParseHexOrDec(GetArg("sccrc", "0x781B988E"));
byte[] sctsBytes    = ParseSnn(GetArg("scts", "4D8E_00ED_0DB6"));

var format = SafetyFormat.Extended;

Console.WriteLine($"=== CIP Safety Scanner → 1734 ===");
Console.WriteLine($"Target: {targetIp}, Backplane Slot: {backplaneSlot}");
Console.WriteLine();

// ----------------------------------------------------------------------------
// UNID & SCID setup
// ----------------------------------------------------------------------------
var ourSnn      = new SafetyNetworkNumber(ourSnnBytes);
var ourOunid    = new UniqueNetworkId { Snn = ourSnn, NodeAddress = ourNode };

var targetSnn   = new SafetyNetworkNumber(tgtSnnBytes);
var targetTunid = new UniqueNetworkId { Snn = targetSnn, NodeAddress = tgtNode };

var scid = new SafetyConfigurationId
{
    Sccrc = sccrc,
    Scts  = new SafetyNetworkNumber(sctsBytes),
};

// ----------------------------------------------------------------------------
// Route to the module: through 1734-ENT backplane port 1, link address = slot
// ----------------------------------------------------------------------------
var routePrefix = new byte[] { 0x01, backplaneSlot };

// ----------------------------------------------------------------------------
// Electronic key for the 1734-IB8S (safety discrete input). Forward Open
// validates this against the actual module before allowing connection.
// Format 4: vendor(2) deviceType(2) productCode(2) compat+major(1) minor(1)
// Compatibility bit set = "Major must match, Minor must be >= specified"
// ----------------------------------------------------------------------------
var electronicKey = new byte[]
{
    0x34, 0x04,                 // Electronic key, format 4 (10 bytes following)
    0x01, 0x00,                 // Vendor: 0x0001 (Rockwell)
    0x23, 0x00,                 // Device Type: 0x0023 (Safety Discrete I/O)
    0x10, 0x00,                 // Product Code: 0x0010
    0x82,                       // Compatibility bit set | Major Rev 2
    0x02,                       // Minor Rev 2
};

// ----------------------------------------------------------------------------
// Application path = electronic key + the three assembly instances
//   - Server: config + consumed(OT) + produced(TO)
//   - Client: config + consumed(OT) + produced(TO)
//
// Assembly instances for 1734-IB8S are >= 256 so we need 16-bit instance
// encoding (0x25 0x00 then the LE instance). For smaller instances we use
// the 8-bit form (0x24 then the byte).
// ----------------------------------------------------------------------------
static byte[] AssemblyInstance(uint instance)
{
    if (instance <= 0xFF)
        return new byte[] { 0x20, 0x04, 0x24, (byte)instance };
    return new byte[] { 0x20, 0x04, 0x25, 0x00, (byte)(instance & 0xFF), (byte)(instance >> 8) };
}

// Server: target produces TCOO to us (T→O), we produce safety data (O→T)
// Client: target produces safety data (T→O), we produce TCOO (O→T)
//
// Note: for the 1734-IB8S, the SERVER pair uses config=0x360, OT=0x234, TO=0xC7
// and the CLIENT pair uses config=0x360, OT=0xC7, TO=0x244.
var serverAppPath = Concat(electronicKey,
    AssemblyInstance(0x0360),
    AssemblyInstance(0x0234),
    AssemblyInstance(0xC7));

var clientAppPath = Concat(electronicKey,
    AssemblyInstance(0x0360),
    AssemblyInstance(0xC7),
    AssemblyInstance(0x0244));

Console.WriteLine($"Server path ({serverAppPath.Length}B): {Hex(serverAppPath)}");
Console.WriteLine($"Client path ({clientAppPath.Length}B): {Hex(clientAppPath)}");
Console.WriteLine();

// ----------------------------------------------------------------------------
// Connection configs
//
// "Server" connection: we are the safety data PRODUCER (originator → target
// for data). The target produces TCOO (Time Coordination) back to us.
// "Client" connection: target is the data producer, we send TCOO back.
//
// Each direction's RPI determines how often that side produces data on that
// connection. PingIntervalMultiplier sets how often the producer toggles the
// ping counter (triggers TCOO exchange).
// ----------------------------------------------------------------------------
var serverConfig = new SafetyForwardOpenConfig
{
    ConfigAssembly                 = 0x0360,
    ConsumedAssembly               = 0x0234,
    ProducedAssembly               = 0xC7,
    ConsumedDataSize               = 1,           // 1 byte safety data
    ProducedDataSize               = 1,
    OtoTRpi                        = 20_000,      // O→T 20ms (data we send to target)
    TtoORpi                        = 380_000,     // T→O 380ms (TCOO from target)
    OtoTConnectionSize             = 7,           // WireSize(1, Extended) = 7
    TtoOConnectionSize             = 6,           // TCOO message size = 6
    Format                         = format,
    Tunid                          = targetTunid,
    Ounid                          = ourOunid,
    Scid                           = scid,
    PingIntervalMultiplier         = 19,
    TimeCoordMsgMinMultiplier      = 0,
    NetworkTimeExpectationMultiplier = 625,       // 625 × 128µs = 80ms
    TimeoutMultiplier              = 2,
    MaxFaultNumber                 = 2,
    InitialTimestamp               = 0xFFFF,
    InitialRolloverValue           = 0xFFFF,
    ConnectionTimeoutMultiplier    = 1,           // *8 per CIP encoding
    PriorityTimeTick               = 0x05,
    TimeoutTicks                   = 156,
};

var clientConfig = new SafetyForwardOpenConfig
{
    ConfigAssembly                 = 0x0360,
    ConsumedAssembly               = 0xC7,
    ProducedAssembly               = 0x0244,
    ConsumedDataSize               = 1,
    ProducedDataSize               = 1,
    OtoTRpi                        = 1_000_000,   // O→T 1000ms (TCOO we send)
    TtoORpi                        = 10_000,      // T→O 10ms (data from target)
    OtoTConnectionSize             = 6,
    TtoOConnectionSize             = 7,
    Format                         = format,
    Tunid                          = targetTunid,
    Ounid                          = ourOunid,
    Scid                           = scid,
    PingIntervalMultiplier         = 100,
    TimeCoordMsgMinMultiplier      = 0,
    NetworkTimeExpectationMultiplier = 313,       // ~40ms
    TimeoutMultiplier              = 2,
    MaxFaultNumber                 = 2,
    InitialTimestamp               = 0xFFFF,      // Target fills in via app reply
    InitialRolloverValue           = 0xFFFF,
    ConnectionTimeoutMultiplier    = 1,
    PriorityTimeTick               = 0x05,
    TimeoutTicks                   = 156,
};

// ----------------------------------------------------------------------------
// Connect: open TCP session, register, then open the safety connection pair
// ----------------------------------------------------------------------------
var scanner = new EipScanner();
Console.Write($"Connecting to {targetIp}:44818...");
await scanner.ConnectAsync(IPAddress.Parse(targetIp));
Console.WriteLine(" OK");

// UDP transport for the I/O data (CIP Class 6 over UDP port 2222)
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

    // Set our outgoing safe data. 0x00 = safe state (outputs off).
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

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
static byte[] Concat(params byte[][] arrays)
{
    int total = arrays.Sum(a => a.Length);
    var result = new byte[total];
    int off = 0;
    foreach (var a in arrays) { a.CopyTo(result, off); off += a.Length; }
    return result;
}

static string Hex(byte[] data) => string.Join(" ", data.Select(b => b.ToString("X2")));
