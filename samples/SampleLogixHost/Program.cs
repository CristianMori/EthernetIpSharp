// SampleLogixHost — minimal Logix tag-server host used by the pycomm3
// round-trip test. Exposes every atomic CIP type the server supports so an
// external client (pycomm3, Studio 5000, PlcSim Advanced, etc.) can prove
// each type reads and writes correctly over the wire.
//
// Usage:  SampleLogixHost [--port <N>] [--bind <ip>]
//   defaults: 127.0.0.1:44818
//
// The tag names and initial values intentionally match the Python port's
// tests/pycomm3/test_pycomm3_roundtrip.py so one test driver can be pointed
// at either server.

using System.Globalization;
using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;
using EthernetIPSharp.Protocol;

string bind = "127.0.0.1";
int port = 44818;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--port":
        case "-p":
            if (i + 1 >= args.Length) { PrintUsage(); return 2; }
            port = int.Parse(args[++i], CultureInfo.InvariantCulture);
            break;
        case "--bind":
        case "-b":
            if (i + 1 >= args.Length) { PrintUsage(); return 2; }
            bind = args[++i];
            break;
        case "-h":
        case "--help":
            PrintUsage(); return 0;
        default:
            Console.Error.WriteLine($"Unknown argument: {args[i]}");
            PrintUsage();
            return 2;
    }
}

var identity = new IdentityInfo
{
    VendorId      = 1,
    DeviceType    = 0x0E,
    ProductCode   = 65,
    MajorRevision = 20,
    MinorRevision = 11,
    SerialNumber  = 0x12345678,
    ProductName   = "EthernetIPSharp SampleLogixHost",
    Status        = 0x0000,
};

var tags = new TagDatabase();

// Atomics — names and initial values mirror the Python round-trip test.
tags.AddTag("TestBool",  LogixDataTypes.BOOL ).Write<byte>  (0, 0x01);
tags.AddTag("TestSint",  LogixDataTypes.SINT ).Write<sbyte> (0, -5);
tags.AddTag("TestInt",   LogixDataTypes.INT  ).Write<short> (0, -1234);
tags.AddTag("TestDint",  LogixDataTypes.DINT ).Write<int>   (0, -1_000_000);
tags.AddTag("TestLint",  LogixDataTypes.LINT ).Write<long>  (0, -1L);
tags.AddTag("TestUsint", LogixDataTypes.USINT).Write<byte>  (0, 42);
tags.AddTag("TestUint",  LogixDataTypes.UINT ).Write<ushort>(0, 0xBEEF);
tags.AddTag("TestUdint", LogixDataTypes.UDINT).Write<uint>  (0, 0xDEADBEEFu);
tags.AddTag("TestUlint", LogixDataTypes.ULINT).Write<ulong> (0, 1_234_567_890_123UL);
tags.AddTag("TestReal",  LogixDataTypes.REAL ).Write<float> (0, 3.14f);
tags.AddTag("TestLreal", LogixDataTypes.LREAL).Write<double>(0, 3.141592653589793);

// Bit strings — stored as raw little-endian bytes; pycomm3 unpacks them to
// per-bit boolean lists.
tags.AddTag("TestByte",  LogixDataTypes.BYTE ).Write<byte>  (0, 0xAB);
tags.AddTag("TestWord",  LogixDataTypes.WORD ).Write<ushort>(0, 0x1234);
tags.AddTag("TestDword", LogixDataTypes.DWORD).Write<uint>  (0, 0xDEADBEEFu);
tags.AddTag("TestLword", LogixDataTypes.LWORD).Write<ulong> (0, 0x123456789ABCDEF0UL);

// SHORT_STRING — left empty; pycomm3 writes "hello" and reads it back.
tags.AddTag("TestShortString", LogixDataTypes.SHORT_STRING);

var dispatcher = new LogixDispatcher(tags, identity);
var adapter    = new EipAdapter(dispatcher, identity);

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

await adapter.ListenAsync(IPAddress.Parse(bind), port, cts.Token);

Console.WriteLine($"SampleLogixHost listening on {bind}:{port}");
Console.WriteLine("Tags: TestBool, TestSint, TestInt, TestDint, TestLint, TestUsint, " +
                  "TestUint, TestUdint, TestUlint, TestReal, TestLreal, TestByte, " +
                  "TestWord, TestDword, TestLword, TestShortString");
Console.WriteLine("Ready. Press Ctrl+C to stop.");
Console.Out.Flush();

try
{
    await Task.Delay(Timeout.Infinite, cts.Token);
}
catch (OperationCanceledException) { }

await adapter.DisposeAsync();
return 0;

static void PrintUsage()
{
    Console.Error.WriteLine("Usage: SampleLogixHost [--port <N>] [--bind <ip>]");
    Console.Error.WriteLine("  defaults: 127.0.0.1:44818");
}
