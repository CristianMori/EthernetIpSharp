using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Tests for gap 1 (program-scoped tags). Acceptance criterion from the requirements
// doc: TagClient reads/writes Program:Cell.Timer1.PRE and a controller tag Timer1
// with the same name, without either shadowing the other.
public class ProgramScopeTests
{
    [Fact]
    public void RegisterProgram_IsIdempotent()
    {
        var db = new TagDatabase();
        var a = db.RegisterProgram("MainProgram");
        var b = db.RegisterProgram("MainProgram");
        Assert.Same(a, b);
    }

    [Fact]
    public void RegisterProgram_IsCaseInsensitive()
    {
        var db = new TagDatabase();
        var a = db.RegisterProgram("mainProgram");
        var b = db.FindProgram("MAINPROGRAM");
        Assert.Same(a, b);
    }

    [Fact]
    public void ProgramTag_And_ControllerTag_ShareName_Independent()
    {
        var db = new TagDatabase();
        var controllerTimer = db.AddTag("Timer1", LogixDataTypes.DINT);
        controllerTimer.Write<int>(0, 111);
        var program = db.RegisterProgram("Cell");
        var programTimer = program.AddTag("Timer1", LogixDataTypes.DINT);
        programTimer.Write<int>(0, 222);

        Assert.Equal(111, db.FindByName("Timer1")!.Read<int>(0));
        Assert.Equal(222, program.FindByName("Timer1")!.Read<int>(0));
    }

    [Fact]
    public void Dispatcher_ReadsProgramScopedTag_ByPath()
    {
        var db = new TagDatabase();
        var timerTpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        db.AddTag("Timer1", timerTpl).Write<int>(0, 11111);  // controller Timer1.PRE
        var program = db.RegisterProgram("Cell");
        program.AddTag("Timer1", timerTpl).Write<int>(0, 22222);  // program Timer1.PRE

        var logix = new LogixDispatcher(db);
        var req = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(req, 1);

        // Controller-scope read.
        var ctrlPath = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("Timer1"),
                new SymbolicPathSegment("PRE"),
            },
        };
        var ctrlResp = logix.Dispatch(TagServices.ReadTag, ctrlPath, req);

        Assert.True(ctrlResp.Status.IsSuccess);
        Assert.Equal(11111, BinaryPrimitives.ReadInt32LittleEndian(ctrlResp.Data.Span.Slice(2)));

        // Program-scope read via Program:Cell prefix.
        var progPath = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("Program:Cell"),
                new SymbolicPathSegment("Timer1"),
                new SymbolicPathSegment("PRE"),
            },
        };
        var progResp = logix.Dispatch(TagServices.ReadTag, progPath, req);

        Assert.True(progResp.Status.IsSuccess, $"status=0x{progResp.Status.GeneralStatus:X2}");
        Assert.Equal(22222, BinaryPrimitives.ReadInt32LittleEndian(progResp.Data.Span.Slice(2)));
    }

    [Fact]
    public void Dispatcher_WritesProgramScopedTag_ByPath()
    {
        var db = new TagDatabase();
        var program = db.RegisterProgram("Cell");
        var tag = program.AddTag("Rate", LogixDataTypes.DINT);

        var logix = new LogixDispatcher(db);
        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("Program:Cell"),
                new SymbolicPathSegment("Rate"),
            },
        };
        var write = new byte[4 + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(write, LogixDataTypes.DINT);
        BinaryPrimitives.WriteUInt16LittleEndian(write.AsSpan(2), 1);
        BinaryPrimitives.WriteInt32LittleEndian(write.AsSpan(4), 4242);

        var resp = logix.Dispatch(TagServices.WriteTag, path, write);

        Assert.True(resp.Status.IsSuccess, $"status=0x{resp.Status.GeneralStatus:X2}");
        Assert.Equal(4242, tag.Read<int>(0));
    }

    [Fact]
    public void Dispatcher_UnknownProgram_ReturnsPathDestinationUnknown()
    {
        var db = new TagDatabase();
        var logix = new LogixDispatcher(db);
        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("Program:NoSuchProgram"),
                new SymbolicPathSegment("AnyTag"),
            },
        };
        var req = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(req, 1);

        var resp = logix.Dispatch(TagServices.ReadTag, path, req);

        Assert.Equal(0x05, resp.Status.GeneralStatus);
    }

    [Fact]
    public void SymbolObject_ControllerBrowse_IncludesProgramPseudoTags()
    {
        var db = new TagDatabase();
        db.AddTag("rate", LogixDataTypes.DINT);
        db.RegisterProgram("MainProgram");
        db.RegisterProgram("Cell");

        var logix = new LogixDispatcher(db);

        // Get_Instance_Attribute_List asks for [attr 1 (name), attr 2 (symbol type)].
        var reqData = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(reqData, 2);
        BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(4), 2);

        var path = new CipPath { ClassId = 0x6B, InstanceId = 0 };
        var resp = logix.Dispatch(0x55, path, reqData);

        Assert.True(resp.Status.IsSuccess);

        // Parse the response and confirm the two program pseudo-tags appear.
        var names = new List<string>();
        var span = resp.Data.Span;
        int off = 0;
        while (off < span.Length)
        {
            off += 4; // instance id
            ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(off));
            off += 2;
            var name = System.Text.Encoding.ASCII.GetString(span.Slice(off, nameLen));
            off += nameLen;
            off += 2; // symbol type
            names.Add(name);
        }

        Assert.Contains("rate", names);
        Assert.Contains("Program:MainProgram", names);
        Assert.Contains("Program:Cell", names);
    }
}
