using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;
using EthernetIPSharp.Device;
using EthernetIPSharp.Protocol;
using EthernetIPSharp.Safety;

// Select profile: "echo" or "plc" (default: echo)
string profile = args.Length > 0 ? args[0].ToLower() : "echo";

IdentityInfo identity;
SafetyNetworkNumber snn;
uint nodeAddress;
IPAddress bindAddress;
int[] assemblies; // [data1, data2, config]

if (profile == "plc")
{
    // Real ControlLogix PLC at 192.168.1.96
    identity = new IdentityInfo
    {
        VendorId = 1, DeviceType = 0, ProductCode = 26,
        MajorRevision = 1, MinorRevision = 1,
        SerialNumber = 0xC0FFEE42,
        ProductName = "EthernetIPSharp Safety Module",
    };
    // SNN: 4D8D_00B4_12C9
    snn = new SafetyNetworkNumber(new byte[] { 0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D });
    nodeAddress = 0xC0A80154; // 192.168.1.84
    bindAddress = IPAddress.Parse("192.168.1.84");
    assemblies = [1, 199, 199]; // data, coordination, config
}
else
{
    // Logix Echo at 192.168.204.128
    identity = new IdentityInfo
    {
        VendorId = 12, DeviceType = 0, ProductCode = 26,
        MajorRevision = 1, MinorRevision = 1,
        SerialNumber = 0xC0FFEE42,
        ProductName = "EthernetIPSharp Safety Module",
    };
    // SNN: 4D90_0101_A35C
    snn = new SafetyNetworkNumber(new byte[] { 0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D });
    nodeAddress = 0xC0A8CC01; // 192.168.204.1
    bindAddress = IPAddress.Parse("192.168.204.1");
    assemblies = [1, 2, 197]; // input, output, config
}

Log($"=== EthernetIPSharp Safety Adapter ({profile}) ===");

await using var device = new SafetyDevice(identity, bindAddress, snn, nodeAddress, "SafeTest");

var safetyData1 = device.AddAssembly((uint)assemblies[0], 1, "Safety Data 1");
var safetyData2 = device.AddAssembly((uint)assemblies[1], 1, "Safety Data 2");
var config = device.AddAssembly((uint)assemblies[2], 0, "Configuration");
// Add assemblies 198/199 for echo if not already added
if (profile == "echo")
{
    device.AddAssembly(198, 1, "Safety Input 198");
    device.AddAssembly(199, 1, "Safety Output 199");
}

safetyData1.Write<byte>(0, 0x42);

Log($"Profile: {profile}, Bind: {bindAddress}, Node: 0x{nodeAddress:X8}");
Log($"Assemblies: {assemblies[0]}, {assemblies[1]}, config={assemblies[2]}");

int connCount = 0;
device.ConnectionManager.ConnectionEstablished += conn =>
{
    connCount++;
    Log($"[CONN #{connCount}] Serial={conn.ConnectionSerialNumber} Class={conn.TransportClass} Safety={conn.IsSafety}");
    Log($"  O->T: Asm {conn.ConsumedAssemblyInstance}, {conn.OtoTSize}B, RPI={conn.OtoTRpi/1000.0}ms");
    Log($"  T->O: Asm {conn.ProducedAssemblyInstance}, {conn.TtoOSize}B, RPI={conn.TtoORpi/1000.0}ms");
    if (conn.IsSafety)
        Log($"  Safety Fmt={conn.SafetyFormat} S1=0x{conn.SafetyPidSeedS1:X2} S3=0x{conn.SafetyPidSeedS3:X4}");
};

var connOpenTimes = new Dictionary<int, DateTime>();
device.ConnectionManager.ConnectionRemoved += conn =>
{
    Log($"[CONN CLOSED] Serial={conn.ConnectionSerialNumber} State={conn.State}");
    if (connOpenTimes.TryGetValue(conn.ConnectionSerialNumber, out var opened))
    {
        var duration = DateTime.UtcNow - opened;
        Log($"  Duration: {duration.TotalSeconds:F1}s");
        if (duration.TotalSeconds > 60)
        {
            Log($"  *** CONNECTION DROPPED AFTER {duration.TotalSeconds:F1}s — HALTING ***");
            Environment.Exit(1);
        }
        connOpenTimes.Remove(conn.ConnectionSerialNumber);
    }
};
device.ConnectionManager.ConnectionEstablished += conn =>
    connOpenTimes[conn.ConnectionSerialNumber] = DateTime.UtcNow;

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

await device.StartAsync(cts.Token);

Log("CIP objects:");
foreach (var cls in device.Dispatcher.RegisteredClasses)
    Log($"  0x{cls.Key:X04} - {cls.Value.Name}");
Log("Ready. Ctrl+C to stop.");
Log("");

int tick = 0;
while (true)
{
    try
    {
        await Task.Delay(500, cts.Token);
    }
    catch (OperationCanceledException) { break; }

    tick++;
    byte d = safetyData1.Read<byte>(0);
    int conns = device.ConnectionManager.ActiveConnections.Count;
    Console.Write($"\r[{DateTime.Now:HH:mm:ss}] Data=0x{d:X2} Conns={conns} T->O={device.TtoOSendCount}    ");
    if (tick % 10 == 0) Console.WriteLine();
}
Log("\nDone.");

static void Log(string msg) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {msg}");
