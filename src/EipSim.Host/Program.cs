using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using EipSim.Cip;
using EipSim.Connections;
using EipSim.Device;
using EipSim.Protocol;

// === Configuration matching Studio 5000 Generic Ethernet Module ===
// Type:   ETHERNET-MODULE Generic Ethernet Module
// Name:   test
// IP:     192.168.1.84
// Format: Data - DINT
// Input  (T->O): Assembly 100, 125 DINTs = 500 bytes
// Output (O->T): Assembly 101, 124 DINTs = 496 bytes
// Config:        Assembly 10,  0 bytes

var bindAddress = IPAddress.Parse("192.168.1.84");

var identity = new IdentityInfo
{
    VendorId = 0x0001,         // Rockwell Automation
    DeviceType = 0x000C,       // Communications Adapter
    ProductCode = 0x0001,
    MajorRevision = 1,
    MinorRevision = 0,
    SerialNumber = 0xC0FFEE42,
    ProductName = "EipSim Echo Module",
    Status = 0x0000,
};

Log("=== EipSim Echo Module ===");
Log($"Bind address: {bindAddress}");
Log($"TCP port:     {EipAdapter.DefaultPort}");
Log($"UDP port:     {EipUdpTransport.IoPort}");
Log("");

await using var device = new VirtualDevice(identity, bindAddress, "test");

// Assemblies per Studio config
var produced = device.AddAssembly(100, 500, "T->O Input (125 DINTs)");
var consumed = device.AddAssembly(101, 496, "O->T Output (124 DINTs)");
device.AddAssembly(10, 0, "Configuration");

// Fill produced data with a ramp pattern so PLC sees non-zero data immediately
for (int i = 0; i < 125; i++)
    produced.Write(i * 4, i + 1);

Log("Assemblies configured:");
Log($"  Instance 100: T->O  500 bytes (125 DINTs) - pre-filled with ramp 1..125");
Log($"  Instance 101: O->T  496 bytes (124 DINTs) - waiting for PLC writes");
Log($"  Instance  10: Config  0 bytes");
Log("");

// --- Connection lifecycle ---
int connectionCount = 0;

device.ConnectionManager.ConnectionEstablished += conn =>
{
    connectionCount++;
    Log($"[CONN OPEN] #{connectionCount}");
    Log($"  Serial:        {conn.ConnectionSerialNumber}");
    Log($"  Originator:    Vendor=0x{conn.OriginatorVendorId:X4}, Serial=0x{conn.OriginatorSerialNumber:X8}");
    Log($"  O->T:          Assembly {conn.ConsumedAssemblyInstance}, {conn.OtoTSize} bytes, RPI={conn.OtoTRpi / 1000.0}ms");
    Log($"  T->O:          Assembly {conn.ProducedAssemblyInstance}, {conn.TtoOSize} bytes, RPI={conn.TtoORpi / 1000.0}ms");
    Log($"  Transport:     Class {(int)conn.TransportClass}");
    Log($"  Timeout:       x{GetMultiplier(conn.TimeoutMultiplier)} ({conn.ConnectionTimeout.TotalMilliseconds}ms)");
    Log($"  Connection IDs: O->T=0x{conn.OtoTConnectionId:X8}, T->O=0x{conn.TtoOConnectionId:X8}");
    Log($"  RemoteEndpoint: {conn.RemoteEndpoint?.ToString() ?? "NULL"}");
};

// Also log when ConnectionOpened fires from the adapter (sets RemoteEndpoint)
device.ConnectionManager.ConnectionEstablished += conn =>
{
    // Check after a short delay if RemoteEndpoint got set
    Task.Delay(50).ContinueWith(_ =>
        Log($"[CONN CHECK] Serial={conn.ConnectionSerialNumber} RemoteEndpoint={conn.RemoteEndpoint?.ToString() ?? "STILL NULL"} State={conn.State}"));
};

device.ConnectionManager.ConnectionRemoved += conn =>
{
    Log($"[CONN CLOSED] Serial={conn.ConnectionSerialNumber}, State={conn.State}");
    if (conn.State == ConnectionState.TimedOut)
        Log("  (timed out - PLC stopped sending)");
};

// --- I/O data monitoring ---
int otPacketCount = 0;
DateTime lastOtLog = DateTime.MinValue;

consumed.DataChanged += (instanceId, data) =>
{
    otPacketCount++;
    var now = DateTime.UtcNow;

    // Log first packet, then every 5 seconds to avoid flooding
    if (otPacketCount == 1 || (now - lastOtLog).TotalSeconds >= 5)
    {
        var bytes = data.ToArray();
        int dint0 = BinaryPrimitives.ReadInt32LittleEndian(bytes);
        int dint1 = bytes.Length >= 8 ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4)) : 0;
        int dint2 = bytes.Length >= 12 ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8)) : 0;

        Log($"[O->T DATA] Packet #{otPacketCount} ({data.Length} bytes)");
        Log($"  DINT[0]={dint0}, DINT[1]={dint1}, DINT[2]={dint2} ...");

        lastOtLog = now;
    }
};

// --- Start ---
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
    Log("  You can add it with: netsh interface ip add address \"Ethernet\" 192.168.1.84 255.255.255.0");
    return;
}

Log("");
Log("Registered CIP objects:");
foreach (var cls in device.Dispatcher.RegisteredClasses)
    Log($"  0x{cls.Key:X04} - {cls.Value.Name}");

Log("");
Log("Ready. Waiting for PLC connection...");
Log("  - The PLC should connect via TCP 44818 and send Forward Open");
Log("  - Works with both real PLCs and FactoryTalk Logix Emulate");
Log("  - Press Ctrl+C to stop");
Log("");

// --- Main loop: update produced data periodically ---
int tick = 0;
try
{
    while (!cts.Token.IsCancellationRequested)
    {
        await Task.Delay(200, cts.Token);
        tick++;

        // Read first DINT of consumed assembly (O->T Output — what PLC writes to us)
        int outputDint0 = consumed.Read<int>(0);

        // Increment DINT[0] of produced assembly (T->O Input — what PLC reads from us)
        produced.Write(0, tick);

        // Print every tick (200ms)
        int activeConns = device.ConnectionManager.ActiveConnections.Count;
        Console.Write($"\r[{DateTime.Now:HH:mm:ss.fff}] Output[0]={outputDint0,10}  |  Input[0]={tick,10}  |  Conns={activeConns}  O->T rx={otPacketCount}  T->O tx={device.TtoOSendCount}    ");

        // Full status line every 5 seconds
        if (tick % 25 == 0)
        {
            Console.WriteLine();
        }
    }
}
catch (OperationCanceledException) { }

Log($"[SHUTDOWN] Total O->T packets received: {otPacketCount}");
Log("[SHUTDOWN] Done.");

// --- Helpers ---

static void Log(string message)
{
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {message}");
}

static int GetMultiplier(byte value) => value switch
{
    0 => 4, 1 => 8, 2 => 16, 3 => 32, 4 => 64, 5 => 128, 6 => 256, 7 => 512, _ => 4,
};
