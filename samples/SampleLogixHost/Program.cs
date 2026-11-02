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

using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;
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

// ----- Yellow-row coverage ---------------------------------------------
// 1-D array of atomics (DintArr[10]), bit of atomic (FlagsDint), BOOL array
// (Flags32), multi-dim array (Matrix[2,3]).  Names + seed values mirror the
// Python test's _spawn_server function one-for-one.
var dintArr = tags.AddTag("DintArr", LogixDataTypes.DINT, elementCount: 10);
for (int i = 0; i < 10; i++) dintArr.Write<int>(i * 4, 100 + i);

tags.AddTag("FlagsDint", LogixDataTypes.DINT).Write<uint>(0, 0b1010_1010_1010_1010u);
tags.AddTag("Flags32", LogixDataTypes.BOOL, elementCount: 32);

var matrix = tags.AddTag("Matrix", LogixDataTypes.DINT, new uint[] { 2, 3 });
for (int r = 0; r < 2; r++)
    for (int c = 0; c < 3; c++)
        matrix.Write<int>((r * 3 + c) * 4, 10 * r + c);

// Logix STRING UDT (LEN:DINT + DATA:SINT[82], 88 bytes on the wire).
var stringTpl = tags.AddTemplate("STRING",
    new TemplateMember("LEN",  LogixDataTypes.DINT),
    new TemplateMember("DATA", LogixDataTypes.SINT, arraySize: 82));
var greeting = tags.AddTag("Greeting", stringTpl);
{
    var buf = new byte[(int)stringTpl.StructureSize];
    byte[] hello = Encoding.ASCII.GetBytes("Hello pycomm3");
    BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0), hello.Length);
    Array.Copy(hello, 0, buf, 4, hello.Length);
    greeting.SetData(buf);
}
tags.AddTag("GreetingArr", stringTpl, elementCount: 3);

// User UDT with REAL + BOOL + DINT members.
var motorTpl = tags.AddTemplate("Motor",
    new TemplateMember("Speed",    LogixDataTypes.REAL),
    new TemplateMember("Fault",    LogixDataTypes.BOOL),
    new TemplateMember("RunCount", LogixDataTypes.DINT));
var motorA = tags.AddTag("MotorA", motorTpl);
{
    // Seed: Speed=3.14, Fault=true, RunCount=42.  Member offsets come from the
    // template Logix produces: Speed@0 (REAL,4), Fault@4 (BOOL bit 0 of a host
    // SINT), RunCount@8 (DINT, re-aligned to 4).
    var buf = new byte[(int)motorTpl.StructureSize];
    BinaryPrimitives.WriteSingleLittleEndian(buf.AsSpan(0), 3.14f);
    buf[4] = 1;
    BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8), 42);
    motorA.SetData(buf);
}
tags.AddTag("MotorArr", motorTpl, elementCount: 3);

// TIMER / COUNTER / CONTROL / AOI-backing proof: all four are "just UDTs"
// from pycomm3's perspective — same access pattern as Motor.*, same Template
// Object plumbing.  Register a Logix-shape TIMER (EN, TT, DN, PRE, ACC) and
// an AOI-shape UDT and seed them so the test can prove MyTimer.PRE /
// MyTimer.EN / MyAOI.Enable all round-trip.
var timerTpl = tags.AddTemplate("TIMER",
    new TemplateMember("EN",  LogixDataTypes.BOOL),
    new TemplateMember("TT",  LogixDataTypes.BOOL),
    new TemplateMember("DN",  LogixDataTypes.BOOL),
    new TemplateMember("PRE", LogixDataTypes.DINT),
    new TemplateMember("ACC", LogixDataTypes.DINT));
var myTimer = tags.AddTag("MyTimer", timerTpl);
{
    // Layout: EN/TT/DN packed into host SINT byte @ offset 0 (bits 0/1/2);
    // PRE DINT @ offset 4; ACC DINT @ offset 8; total 12 bytes.
    var buf = new byte[(int)timerTpl.StructureSize];
    buf[0] = 0x01;                                          // EN = True
    BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(4), 1000);  // PRE
    BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8), 250);   // ACC
    myTimer.SetData(buf);
}

var aoiTpl = tags.AddTemplate("MixerAOI",
    new TemplateMember("Enable",   LogixDataTypes.BOOL),
    new TemplateMember("Setpoint", LogixDataTypes.REAL),
    new TemplateMember("Done",     LogixDataTypes.BOOL),
    new TemplateMember("Steps",    LogixDataTypes.DINT));
var myAoi = tags.AddTag("MyAOI", aoiTpl);
{
    // Layout: Enable @ host SINT byte 0 bit 0; Setpoint REAL @ offset 4;
    // Done @ host SINT byte 8 bit 0; Steps DINT @ offset 12; total 16 bytes.
    var buf = new byte[(int)aoiTpl.StructureSize];
    buf[0] = 0x01;                                             // Enable = True
    BinaryPrimitives.WriteSingleLittleEndian(buf.AsSpan(4), 42.5f);
    buf[8] = 0x00;                                             // Done = False
    BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(12), 7); // Steps
    myAoi.SetData(buf);
}
// -----------------------------------------------------------------------

// Program-scoped tags: pycomm3 enumerates them under the "Program:<name>."
// prefix (with init_program_tags=True) and reads/writes them via that prefix.
// Register MainProgram with a scalar, a REAL, and a Motor UDT so we exercise
// atomic + member access through program scope.  Names and seed values mirror
// the Python port one-for-one.
var mainProgram = tags.RegisterProgram("MainProgram");
mainProgram.AddTag("LocalDint", LogixDataTypes.DINT).Write<int>(0, 42);
mainProgram.AddTag("LocalReal", LogixDataTypes.REAL).Write<float>(0, 3.14f);
var localMotor = mainProgram.AddTag("LocalMotor", motorTpl);
{
    var buf = new byte[(int)motorTpl.StructureSize];
    BinaryPrimitives.WriteSingleLittleEndian(buf.AsSpan(0), 2.5f);
    buf[4] = 1;                                               // Fault = True
    BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8), 99); // RunCount
    localMotor.SetData(buf);
}

var dispatcher = new LogixDispatcher(tags, identity);
var adapter    = new EipAdapter(dispatcher, identity);

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

await adapter.ListenAsync(IPAddress.Parse(bind), port, cts.Token);

Console.WriteLine($"SampleLogixHost listening on {bind}:{port}");
Console.WriteLine("Tags: TestBool, TestSint, TestInt, TestDint, TestLint, TestUsint, " +
                  "TestUint, TestUdint, TestUlint, TestReal, TestLreal, TestByte, " +
                  "TestWord, TestDword, TestLword, TestShortString, " +
                  "DintArr, FlagsDint, Flags32, Matrix, Greeting, GreetingArr, " +
                  "MotorA, MotorArr, MyTimer, MyAOI");
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
