// Minimal Logix simulator for pycomm3 testing — run with: dotnet script tests/logix_host.cs
// Or compile as a standalone console app

using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;
using EthernetIPSharp.Protocol;

var identity = new IdentityInfo
{
    VendorId = 1,
    DeviceType = 0x0E,
    ProductCode = 55,
    MajorRevision = 32,
    MinorRevision = 11,
    SerialNumber = 0xDEAD,
    ProductName = "EthernetIPSharp Logix",
};

var logix = new LogixDispatcher(new TagDatabase(), identity);

// Add test tags
logix.Tags.AddTag("rate", LogixDataTypes.DINT).Write(0, 534);
logix.Tags.AddTag("temperature", LogixDataTypes.REAL).Write(0, 72.5f);
logix.Tags.AddTag("counts", LogixDataTypes.INT, elementCount: 10);

var adapter = new EipAdapter(logix, identity);
await adapter.ListenAsync(IPAddress.Loopback, 44818);

Console.WriteLine("Logix simulator running on 127.0.0.1:44818");
Console.WriteLine("Tags: rate(DINT)=534, temperature(REAL)=72.5, counts(INT[10])");
Console.WriteLine("Press Ctrl+C to stop.");

await Task.Delay(Timeout.Infinite, new CancellationTokenSource().Token);
