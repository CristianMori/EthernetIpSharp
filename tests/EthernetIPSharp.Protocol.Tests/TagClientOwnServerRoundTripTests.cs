// Our TagClient against our server — the symmetric check to the pycomm3
// round-trip.
//
// pycomm3 verifies that OUR server speaks the Rockwell wire dialect
// correctly. This test verifies that OUR client speaks the same dialect —
// reads back exactly what the server stored (as proven by the pycomm3 test
// against the same server with the same seed values).
//
// Shares the sample-host seed data with the pycomm3 test so the matrix is
// identical: every atomic, 1-D array, bit of atomic, BOOL array, multi-dim
// array, Logix STRING UDT, user UDT whole-struct and member access,
// Timer/AOI UDTs, program-scoped tags, and batch read.
//
// Mirrors ../../../EthernetIPPython/tests/own_client/test_own_client_roundtrip.py
// one-for-one.

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Protocol.Tests;

public class TagClientOwnServerRoundTripTests
{
    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>Build the same tag landscape the pycomm3 test uses.</summary>
    private static (EipAdapter adapter, Task listenTask, TagDatabase tags,
                    TemplateDefinition stringTpl, TemplateDefinition motorTpl,
                    TemplateDefinition timerTpl,  TemplateDefinition aoiTpl,
                    CancellationTokenSource cts, int port)
        SpawnServer()
    {
        var identity = new IdentityInfo
        {
            VendorId      = 1,
            DeviceType    = 0x0E,
            ProductCode   = 65,
            MajorRevision = 20,
            MinorRevision = 11,
            SerialNumber  = 0x12345678,
            ProductName   = "OwnClientRoundTripTarget",
        };

        var tags = new TagDatabase();

        // Atomics
        tags.AddTag("TestDint",  LogixDataTypes.DINT ).Write<int>  (0, -1_000_000);
        tags.AddTag("TestReal",  LogixDataTypes.REAL ).Write<float>(0, 3.14f);
        tags.AddTag("TestUdint", LogixDataTypes.UDINT).Write<uint> (0, 0xDEADBEEFu);
        tags.AddTag("TestLint",  LogixDataTypes.LINT ).Write<long> (0, -1L);
        tags.AddTag("TestShortString", LogixDataTypes.SHORT_STRING);

        // 1-D array of atomics
        var dintArr = tags.AddTag("DintArr", LogixDataTypes.DINT, elementCount: 10);
        for (int i = 0; i < 10; i++) dintArr.Write<int>(i * 4, 100 + i);

        // Bit of atomic
        tags.AddTag("FlagsDint", LogixDataTypes.DINT).Write<uint>(0, 0b1010_1010_1010_1010u);

        // BOOL array (DWORD-packed)
        tags.AddTag("Flags32", LogixDataTypes.BOOL, elementCount: 32);

        // Multi-dim array
        var matrix = tags.AddTag("Matrix", LogixDataTypes.DINT, new uint[] { 2, 3 });
        for (int r = 0; r < 2; r++)
            for (int c = 0; c < 3; c++)
                matrix.Write<int>((r * 3 + c) * 4, 10 * r + c);

        // Logix STRING UDT
        var stringTpl = tags.AddTemplate("STRING",
            new TemplateMember("LEN",  LogixDataTypes.DINT),
            new TemplateMember("DATA", LogixDataTypes.SINT, arraySize: 82));
        var greeting = tags.AddTag("Greeting", stringTpl);
        {
            var buf = new byte[(int)stringTpl.StructureSize];
            byte[] hello = Encoding.ASCII.GetBytes("Hello client");
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0), hello.Length);
            Array.Copy(hello, 0, buf, 4, hello.Length);
            greeting.SetData(buf);
        }

        // User UDT with REAL + BOOL + DINT members
        var motorTpl = tags.AddTemplate("Motor",
            new TemplateMember("Speed",    LogixDataTypes.REAL),
            new TemplateMember("Fault",    LogixDataTypes.BOOL),
            new TemplateMember("RunCount", LogixDataTypes.DINT));
        var motorA = tags.AddTag("MotorA", motorTpl);
        {
            var buf = new byte[(int)motorTpl.StructureSize];
            BinaryPrimitives.WriteSingleLittleEndian(buf.AsSpan(0), 3.14f);
            buf[4] = 1;                                                   // Fault = True
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8), 42);   // RunCount
            motorA.SetData(buf);
        }
        tags.AddTag("MotorArr", motorTpl, elementCount: 3);

        // TIMER-shape and AOI-shape UDTs
        var timerTpl = tags.AddTemplate("TIMER",
            new TemplateMember("EN",  LogixDataTypes.BOOL),
            new TemplateMember("TT",  LogixDataTypes.BOOL),
            new TemplateMember("DN",  LogixDataTypes.BOOL),
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        var myTimer = tags.AddTag("MyTimer", timerTpl);
        {
            var buf = new byte[(int)timerTpl.StructureSize];
            buf[0] = 0x01;                                                      // EN = True
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(4), 1000);       // PRE
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8), 250);        // ACC
            myTimer.SetData(buf);
        }

        var aoiTpl = tags.AddTemplate("MixerAOI",
            new TemplateMember("Enable",   LogixDataTypes.BOOL),
            new TemplateMember("Setpoint", LogixDataTypes.REAL),
            new TemplateMember("Done",     LogixDataTypes.BOOL),
            new TemplateMember("Steps",    LogixDataTypes.DINT));
        var myAoi = tags.AddTag("MyAOI", aoiTpl);
        {
            var buf = new byte[(int)aoiTpl.StructureSize];
            buf[0] = 0x01;                                                     // Enable = True
            BinaryPrimitives.WriteSingleLittleEndian(buf.AsSpan(4), 42.5f);    // Setpoint
            buf[8] = 0x00;                                                     // Done = False
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(12), 7);        // Steps
            myAoi.SetData(buf);
        }

        // Program-scoped tags
        var mainProgram = tags.RegisterProgram("MainProgram");
        mainProgram.AddTag("LocalDint", LogixDataTypes.DINT).Write<int>  (0, 42);
        mainProgram.AddTag("LocalReal", LogixDataTypes.REAL).Write<float>(0, 3.14f);
        var localMotor = mainProgram.AddTag("LocalMotor", motorTpl);
        {
            var buf = new byte[(int)motorTpl.StructureSize];
            BinaryPrimitives.WriteSingleLittleEndian(buf.AsSpan(0), 2.5f);
            buf[4] = 1;                                                        // Fault = True
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8), 99);        // RunCount
            localMotor.SetData(buf);
        }

        var dispatcher = new LogixDispatcher(tags, identity);
        var adapter = new EipAdapter(dispatcher, identity);
        var cts = new CancellationTokenSource();
        int port = GetFreePort();
        var task = adapter.ListenAsync(IPAddress.Loopback, port, cts.Token);
        // Small spin-wait: the loopback accept is near-instant but let the
        // listener bind before the client tries to connect.
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var probe = new TcpClient();
                probe.Connect(IPAddress.Loopback, port);
                break;
            }
            catch { Thread.Sleep(25); }
        }
        return (adapter, task, tags, stringTpl, motorTpl, timerTpl, aoiTpl, cts, port);
    }

    private static async Task Teardown(EipAdapter adapter, Task listenTask, CancellationTokenSource cts)
    {
        cts.Cancel();
        await adapter.DisposeAsync();
        try { await listenTask; } catch { }
        cts.Dispose();
    }

    [Fact]
    public async Task TagClient_FullMatrix_RoundTrips()
    {
        var ctx = SpawnServer();
        var failures = new List<string>();
        try
        {
            var client = new TagClient("127.0.0.1", ctx.port);
            await client.ConnectAsync();
            try
            {
                // --- Atomics -------------------------------------------------
                try
                {
                    Assert.Equal(-1_000_000, await client.ReadAsync<int>("TestDint"));
                    await client.WriteAsync<int>("TestDint", 2_000_000_000);
                    Assert.Equal(2_000_000_000, await client.ReadAsync<int>("TestDint"));

                    Assert.InRange(await client.ReadAsync<float>("TestReal") - 3.14f, -1e-5f, 1e-5f);
                    await client.WriteAsync<float>("TestReal", -2.71828f);
                    Assert.InRange(await client.ReadAsync<float>("TestReal") - (-2.71828f), -1e-4f, 1e-4f);

                    Assert.Equal(0xDEADBEEFu, await client.ReadAsync<uint>("TestUdint"));
                    await client.WriteAsync<uint>("TestUdint", 0xFFFF_FFFFu);
                    Assert.Equal(0xFFFF_FFFFu, await client.ReadAsync<uint>("TestUdint"));

                    Assert.Equal(-1L, await client.ReadAsync<long>("TestLint"));
                    await client.WriteAsync<long>("TestLint", 0x7FFF_FFFF_FFFF_FFFFL);
                    Assert.Equal(0x7FFF_FFFF_FFFF_FFFFL, await client.ReadAsync<long>("TestLint"));

                    // --- 1-D array indexed -----------------------------------
                    Assert.Equal(105, await client.ReadAsync<int>("DintArr[5]"));
                    await client.WriteAsync<int>("DintArr[5]", 999);
                    Assert.Equal(999, await client.ReadAsync<int>("DintArr[5]"));

                    // --- Multi-dim array -------------------------------------
                    Assert.Equal(12, await client.ReadAsync<int>("Matrix[1,2]"));
                    await client.WriteAsync<int>("Matrix[0,1]", 777);
                    Assert.Equal(777, await client.ReadAsync<int>("Matrix[0,1]"));

                    // --- Logix STRING UDT ------------------------------------
                    Assert.Equal("Hello client", await client.ReadStringAsync("Greeting"));
                    // Discover the STRING template's structure handle before
                    // writing (the client requires it, mirroring Studio 5000).
                    var stringTplInfo = await client.ReadTemplateAsync(ctx.stringTpl.InstanceId);
                    await client.WriteStringAsync("Greeting", "written back",
                                                   stringTplInfo.StructureHandle);
                    Assert.Equal("written back", await client.ReadStringAsync("Greeting"));
                }
                catch (Exception exc)
                {
                    failures.Add($"ATOMIC/STRING/MATRIX: {exc}");
                    try { await client.DisconnectAsync(); } catch { }
                    client = new TagClient("127.0.0.1", ctx.port);
                    await client.ConnectAsync();
                }

                // --- UDT whole-struct + member access ------------------------
                try
                {
                    var motorTplInfo = await client.ReadTemplateAsync(ctx.motorTpl.InstanceId);
                    var sv = await client.ReadStructAsync("MotorA", motorTplInfo);
                    Assert.NotNull(sv);
                }
                catch (Exception exc)
                {
                    failures.Add($"MotorA ReadStruct: {exc}");
                }

                try
                {
                    Assert.InRange(await client.ReadAsync<float>("MotorA.Speed") - 3.14f, -1e-5f, 1e-5f);
                    Assert.Equal(42, await client.ReadAsync<int>("MotorA.RunCount"));
                    await client.WriteAsync<float>("MotorA.Speed", -1.5f);
                    Assert.InRange(await client.ReadAsync<float>("MotorA.Speed") - (-1.5f), -1e-4f, 1e-4f);
                }
                catch (Exception exc)
                {
                    failures.Add($"MotorA members: {exc}");
                }

                try
                {
                    await client.WriteAsync<float>("MotorArr[1].Speed", 7.77f);
                    Assert.InRange(await client.ReadAsync<float>("MotorArr[1].Speed") - 7.77f, -1e-4f, 1e-4f);
                }
                catch (Exception exc)
                {
                    failures.Add($"MotorArr member: {exc}");
                }

                // --- Timer / AOI (just UDTs) ---------------------------------
                try
                {
                    Assert.Equal(1000, await client.ReadAsync<int>("MyTimer.PRE"));
                    Assert.Equal(250,  await client.ReadAsync<int>("MyTimer.ACC"));
                    await client.WriteAsync<int>("MyTimer.PRE", 2000);
                    Assert.Equal(2000, await client.ReadAsync<int>("MyTimer.PRE"));

                    Assert.InRange(await client.ReadAsync<float>("MyAOI.Setpoint") - 42.5f, -1e-5f, 1e-5f);
                    await client.WriteAsync<float>("MyAOI.Setpoint", 99.9f);
                    Assert.InRange(await client.ReadAsync<float>("MyAOI.Setpoint") - 99.9f, -1e-4f, 1e-4f);
                    Assert.Equal(7, await client.ReadAsync<int>("MyAOI.Steps"));
                }
                catch (Exception exc)
                {
                    failures.Add($"Timer/AOI: {exc}");
                }

                // --- Program-scoped tags -------------------------------------
                try
                {
                    Assert.Equal(42, await client.ReadAsync<int>("Program:MainProgram.LocalDint"));
                    await client.WriteAsync<int>("Program:MainProgram.LocalDint", 100);
                    Assert.Equal(100, await client.ReadAsync<int>("Program:MainProgram.LocalDint"));

                    Assert.InRange(
                        await client.ReadAsync<float>("Program:MainProgram.LocalReal") - 3.14f,
                        -1e-5f, 1e-5f);

                    Assert.InRange(
                        await client.ReadAsync<float>("Program:MainProgram.LocalMotor.Speed") - 2.5f,
                        -1e-5f, 1e-5f);
                    Assert.Equal(99, await client.ReadAsync<int>("Program:MainProgram.LocalMotor.RunCount"));
                    await client.WriteAsync<float>("Program:MainProgram.LocalMotor.Speed", 5.5f);
                    Assert.InRange(
                        await client.ReadAsync<float>("Program:MainProgram.LocalMotor.Speed") - 5.5f,
                        -1e-4f, 1e-4f);
                }
                catch (Exception exc)
                {
                    failures.Add($"Program scope: {exc}");
                }

                // --- Batch read (multi-service) ------------------------------
                try
                {
                    var got = await client.ReadMultipleAsync(
                        new[] { "DintArr[0]", "DintArr[1]", "DintArr[2]" });
                    Assert.Equal(3, got.Count);
                }
                catch (Exception exc)
                {
                    failures.Add($"batch read: {exc}");
                }

                await client.DisconnectAsync();
            }
            finally
            {
                try { await client.DisposeAsync(); } catch { }
            }
        }
        finally
        {
            await Teardown(ctx.adapter, ctx.listenTask, ctx.cts);
        }

        Assert.True(failures.Count == 0,
            "TagClient round-trip failures:\n" + string.Join("\n", failures));
    }
}
