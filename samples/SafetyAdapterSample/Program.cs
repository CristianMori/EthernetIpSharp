// ============================================================================
// SafetyAdapterSample — CIP Safety EtherNet/IP Adapter (Target)
// ============================================================================
//
// What this sample does:
//   Acts as a CIP Safety I/O adapter (target side). It listens for a safety
//   originator (e.g. a Logix PLC or compatible emulator) and serves a pair of
//   safety connections: one where the PLC produces data to us, and one where
//   WE produce data to the PLC. All frames are CRC-protected and time-coordinated
//   per the CIP Safety specification (Extended Format).
//
// Typical usage:
//   dotnet run --project samples/SafetyAdapterSample                    # test2 profile (default)
//   dotnet run --project samples/SafetyAdapterSample -- --profile=plc
//   dotnet run --project samples/SafetyAdapterSample -- --bind=10.0.0.5 --vendor=12 --snn=4D90_0101_A35C --node=0x0A000005
//
// CLI options (all optional; profile sets defaults you can then override):
//   --profile=<test2|plc>     Picks a preconfigured target. Default: test2
//   --bind=<ip>               Local IP to bind on (must be assigned to a NIC)
//   --vendor=<n>              Vendor ID (12 = synthetic vendor used by some emulators, 1 = Rockwell)
//   --serial=<hex>            32-bit device serial number (hex, e.g. 0xC0FFEE42)
//   --product=<text>          Product name string returned by Identity object
//   --snn=<hex_6bytes>        Safety Network Number (12 hex chars, e.g. 4D90_0101_A35C)
//   --node=<hex>              Safety node address (your IP encoded as uint32, big-endian)
//   --asm-data1=<n>           First safety data assembly instance
//   --asm-data2=<n>           Second safety data assembly instance
//   --asm-config=<n>          Configuration assembly instance
//   --halt-threshold=<sec>    Exit if a connection drops after running this long. Default: 60
// ============================================================================

using System.Net;
using System.Runtime;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Safety;

// Tell the GC to avoid generation 2 collections in the foreground for as long
// as it can (still runs in background). Belt-and-suspenders for the producer
// thread — the hot path is already alloc-free, but this hedges against any
// stray allocation triggering a stop-the-world pause that would compound on
// top of the normal ~10ms Windows scheduler tail.
GCSettings.LatencyMode = GCLatencyMode.SustainedLowLatency;

// ----------------------------------------------------------------------------
// Minimal --key=value argument parser (no external deps).
// Returns the value for --key=... or the supplied default if absent.
// ----------------------------------------------------------------------------
string GetArg(string key, string defaultValue)
{
    var match = args.FirstOrDefault(a => a.StartsWith($"--{key}=", StringComparison.OrdinalIgnoreCase));
    return match is null ? defaultValue : match[(match.IndexOf('=') + 1)..];
}

// ----------------------------------------------------------------------------
// Profile selects the default values. You can override any field with --key=...
// ----------------------------------------------------------------------------
string profile = GetArg("profile", "test2").ToLowerInvariant();

// --- Profile defaults ---
ushort defaultVendor;
uint defaultSerial = 0xC0FFEE42;
string defaultProduct = "EthernetIPSharp Safety Module";
byte[] defaultSnnBytes;
uint defaultNode;
string defaultBind;
int defaultAsmData1, defaultAsmData2, defaultAsmConfig;

if (profile == "plc")
{
    // Real ControlLogix PLC at 192.168.1.96, our adapter on 192.168.1.84
    defaultVendor    = 1;                                  // Rockwell
    defaultSnnBytes  = new byte[] { 0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D };  // SNN 4D8D_00B4_12C9
    defaultNode      = 0xC0A80154;                         // 192.168.1.84 packed BE
    defaultBind      = "192.168.1.84";
    defaultAsmData1  = 1;                                  // Safety input
    defaultAsmData2  = 199;                                // Safety output / coordination
    defaultAsmConfig = 199;                                // Configuration
}
else
{
    // Synthetic safety scanner on 192.168.204.0/24 (e.g. a VM-based emulator)
    defaultVendor    = 12;                                 // Synthetic vendor used by some emulators
    defaultSnnBytes  = new byte[] { 0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D };  // SNN 4D90_0101_A35C
    defaultNode      = 0xC0A8CC01;                         // 192.168.204.1 packed BE
    defaultBind      = "192.168.204.1";
    defaultAsmData1  = 1;
    defaultAsmData2  = 2;
    defaultAsmConfig = 197;
}

// --- CLI overrides (all optional; fall through to profile defaults) ---
ushort vendorId           = ushort.Parse(GetArg("vendor", defaultVendor.ToString()));
uint   serialNumber       = ParseHexOrDec(GetArg("serial", $"0x{defaultSerial:X8}"));
string productName        = GetArg("product", defaultProduct);
byte[] snnBytes           = ParseSnn(GetArg("snn", FormatSnn(defaultSnnBytes)));
uint   nodeAddress        = ParseHexOrDec(GetArg("node",   $"0x{defaultNode:X8}"));
IPAddress bindAddress     = IPAddress.Parse(GetArg("bind", defaultBind));
int    asmData1           = int.Parse(GetArg("asm-data1", defaultAsmData1.ToString()));
int    asmData2           = int.Parse(GetArg("asm-data2", defaultAsmData2.ToString()));
int    asmConfig          = int.Parse(GetArg("asm-config", defaultAsmConfig.ToString()));
double haltThresholdSec   = double.Parse(GetArg("halt-threshold", "60"));
int    startupTraceSec    = int.Parse(GetArg("startup-trace", "0"));
EthernetIPSharp.Safety.SafetyDevice.StartupTraceSeconds = startupTraceSec;

// ----------------------------------------------------------------------------
// Build the device identity (what an EtherNet/IP scanner sees in ListIdentity)
// ----------------------------------------------------------------------------
var identity = new IdentityInfo
{
    VendorId      = vendorId,
    DeviceType    = 0,            // 0 = generic device
    ProductCode   = 26,
    MajorRevision = 1,
    MinorRevision = 1,
    SerialNumber  = serialNumber,
    ProductName   = productName,
};

var snn = new SafetyNetworkNumber(snnBytes);

Log($"=== EthernetIPSharp Safety Adapter ({profile}) ===");
Log($"Profile: {profile}, Bind: {bindAddress}, Node: 0x{nodeAddress:X8}");
Log($"Identity: Vendor=0x{vendorId:X4}, Serial=0x{serialNumber:X8}, Name=\"{productName}\"");
Log($"SNN: {FormatSnn(snnBytes)}");
Log($"Assemblies: data1={asmData1}, data2={asmData2}, config={asmConfig}");

// ----------------------------------------------------------------------------
// Create the safety device. The "SafeTest" name only shows up in our own logs.
// ----------------------------------------------------------------------------
await using var device = new SafetyDevice(identity, bindAddress, snn, nodeAddress, "SafeTest");

// ----------------------------------------------------------------------------
// Register assembly instances the safety connection will reference.
// The sizes here are the APPLICATION data sizes (NOT the wire sizes). The
// safety framing overhead is added automatically by SafetyDevice.
//
// Conventions used by typical Logix safety configs:
//   - Two 1-byte safety data assemblies (input + output)
//   - One 0-byte "config" assembly (configuration data sent at connection open)
// ----------------------------------------------------------------------------
var safetyData1 = device.AddAssembly((uint)asmData1, 1, "Safety Data 1");
var safetyData2 = device.AddAssembly((uint)asmData2, 1, "Safety Data 2");
// Logix safety configs often map asmConfig onto one of the data instances.
// Skip the redundant registration when it would replace an existing one.
if (asmConfig != asmData1 && asmConfig != asmData2)
{
    device.AddAssembly((uint)asmConfig, 0, "Configuration");
}

// The test2 profile's scanner also opens assemblies 198 and 199. Add them
// so the Forward Open can resolve the paths.
if (profile == "test2")
{
    device.AddAssembly(198, 1, "Safety Input 198");
    device.AddAssembly(199, 1, "Safety Output 199");
}

// Put a known byte into our produced data so the consumer sees non-zero data
// (handy for visual confirmation in Studio)
safetyData1.Write<byte>(0, 0x42);

// ----------------------------------------------------------------------------
// Connection lifecycle hooks
// ----------------------------------------------------------------------------
int connCount = 0;
var connOpenTimes = new Dictionary<int, DateTime>();

device.ConnectionManager.ConnectionEstablished += conn =>
{
    connCount++;
    connOpenTimes[conn.ConnectionSerialNumber] = DateTime.UtcNow;

    Log($"[CONN #{connCount}] Serial={conn.ConnectionSerialNumber} Class={conn.TransportClass} Safety={conn.IsSafety}");
    Log($"  O->T: Asm {conn.ConsumedAssemblyInstance}, {conn.OtoTSize}B, RPI={conn.OtoTRpi / 1000.0}ms");
    Log($"  T->O: Asm {conn.ProducedAssemblyInstance}, {conn.TtoOSize}B, RPI={conn.TtoORpi / 1000.0}ms");
    if (conn.IsSafety)
        Log($"  Safety Fmt={conn.SafetyFormat} S1=0x{conn.SafetyPidSeedS1:X2} S3=0x{conn.SafetyPidSeedS3:X4}");
};

device.ConnectionManager.ConnectionRemoved += conn =>
{
    Log($"[CONN CLOSED] Serial={conn.ConnectionSerialNumber} State={conn.State}");
    if (connOpenTimes.TryGetValue(conn.ConnectionSerialNumber, out var opened))
    {
        var duration = DateTime.UtcNow - opened;
        Log($"  Duration: {duration.TotalSeconds:F1}s");

        // Halt-on-drop is a debugging aid for soak tests: if a connection that
        // had been up for a while dies unexpectedly, exit so the failure is
        // obvious in CI / pcap correlations.
        if (duration.TotalSeconds > haltThresholdSec)
        {
            Log($"  *** CONNECTION DROPPED AFTER {duration.TotalSeconds:F1}s — HALTING ***");
            Environment.Exit(1);
        }
        connOpenTimes.Remove(conn.ConnectionSerialNumber);
    }
};

// ----------------------------------------------------------------------------
// Start the adapter (TCP listener on port 44818, UDP listener on 2222)
// ----------------------------------------------------------------------------
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

await device.StartAsync(cts.Token);

Log("CIP objects:");
foreach (var cls in device.Dispatcher.RegisteredClasses)
    Log($"  0x{cls.Key:X04} - {cls.Value.Name}");
Log("Ready. Ctrl+C to stop.");
Log("");

// ----------------------------------------------------------------------------
// Heartbeat: every 500ms print the current data byte and connection count.
// Removed once during the 100ms-gap investigation as a suspected source of
// Console contention — turned out the NIC (10Mbps half-duplex) was the real
// cause. Now re-enabled for at-a-glance visibility during long runs.
// ----------------------------------------------------------------------------
int tick = 0;
while (true)
{
    try { await Task.Delay(500, cts.Token); }
    catch (OperationCanceledException) { break; }

    tick++;
    byte d = safetyData1.Read<byte>(0);
    int conns = device.ConnectionManager.ActiveConnections.Count;
    Console.Write($"\r[{DateTime.Now:HH:mm:ss}] Data=0x{d:X2} Conns={conns} T->O={device.TtoOSendCount}    ");
    if (tick % 10 == 0) Console.WriteLine();
}
Log("\nDone.");

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
static void Log(string msg) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {msg}");

// Parse "0x12345678" or "305419896"
static uint ParseHexOrDec(string s)
{
    s = s.Trim();
    if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        return Convert.ToUInt32(s.Substring(2), 16);
    return uint.Parse(s);
}

// Format SNN bytes (little-endian on the wire) as a human-readable string
// like "4D90_0101_A35C" (big-endian visual grouping).
static string FormatSnn(byte[] bytes) =>
    $"{bytes[5]:X2}{bytes[4]:X2}_{bytes[3]:X2}{bytes[2]:X2}_{bytes[1]:X2}{bytes[0]:X2}";

// Parse "4D90_0101_A35C" back to the 6-byte little-endian array.
static byte[] ParseSnn(string s)
{
    var hex = s.Replace("_", "").Replace("-", "").Replace(" ", "");
    if (hex.Length != 12) throw new ArgumentException("SNN must be 12 hex chars (6 bytes)");
    var bytes = new byte[6];
    // Visual is big-endian high to low; on the wire it's little-endian.
    // Reverse the parse so input "4D90_0101_A35C" maps to {5C, A3, 01, 01, 90, 4D}.
    for (int i = 0; i < 6; i++)
        bytes[5 - i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
    return bytes;
}
