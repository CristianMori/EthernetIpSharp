using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

public class TagPathWalkerTests
{
    [Fact]
    public void ResolvesRootScalarWithNoSegments()
    {
        var db = new TagDatabase();
        db.AddTag("rate", LogixDataTypes.DINT);
        var root = db.FindByName("rate")!;

        var ok = TagPathWalker.TryWalk(root, Array.Empty<CipPathSegment>(), db.FindTemplate,
            out var res, out var err);

        Assert.True(ok, err);
        Assert.Equal(0, res.Offset);
        Assert.Equal(LogixDataTypes.DINT, res.TypeCode);
        Assert.Equal(4, res.ElementSize);
        Assert.Null(res.BitPos);
    }

    [Fact]
    public void ResolvesScalarMember()
    {
        var db = new TagDatabase();
        var timerTpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        db.AddTag("t1", timerTpl);
        var root = db.FindByName("t1")!;

        var segs = new CipPathSegment[] { new SymbolicPathSegment("ACC") };

        var ok = TagPathWalker.TryWalk(root, segs, db.FindTemplate, out var res, out var err);

        Assert.True(ok, err);
        Assert.Equal(4, res.Offset); // ACC is second DINT, 4 bytes in.
        Assert.Equal(LogixDataTypes.DINT, res.TypeCode);
        Assert.Equal(4, res.ElementSize);
        Assert.Null(res.BitPos);
    }

    [Fact]
    public void ResolvesNestedStructMember()
    {
        var db = new TagDatabase();
        var timerTpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        // "Motor" carries a nested Timer at the second slot. Nested-struct member
        // support is gap 3; here we simulate the resolved layout the transpiler
        // will hand us: an explicit TemplateDefinition with struct-typed members.
        var motorMembers = new[]
        {
            new TemplateMemberInfo("Speed", LogixDataTypes.REAL, 0, 0, 4),
            new TemplateMemberInfo("Timer", (ushort)(0x8000 | timerTpl.InstanceId), 4, 0, (int)timerTpl.StructureSize),
        };
        var motorTpl = new TemplateDefinition(
            instanceId: 0x201, name: "Motor",
            structureHandle: 0x8201,
            structureSize: 4 + timerTpl.StructureSize,
            members: motorMembers);
        // Poke it into the DB via reflection-free path: use a lookup lambda.
        TemplateDefinition? Templates(ushort id) =>
            id == timerTpl.InstanceId ? timerTpl :
            id == motorTpl.InstanceId ? motorTpl : null;

        var root = new Tag(
            instanceId: 100, name: "m1",
            symbolType: LogixDataTypes.MakeStructSymbolType(motorTpl.InstanceId),
            tagType: motorTpl.StructureHandle,
            elementSize: (int)motorTpl.StructureSize);

        var segs = new CipPathSegment[]
        {
            new SymbolicPathSegment("Timer"),
            new SymbolicPathSegment("PRE"),
        };

        var ok = TagPathWalker.TryWalk(root, segs, Templates, out var res, out var err);

        Assert.True(ok, err);
        Assert.Equal(4, res.Offset); // Motor.Timer @ 4, .PRE @ 0 inside Timer.
        Assert.Equal(LogixDataTypes.DINT, res.TypeCode);
    }

    [Fact]
    public void ResolvesBoolMemberBitPosition()
    {
        var db = new TagDatabase();
        // Three BOOLs pack into one host SINT byte at bit positions 0, 1, 2.
        var tpl = db.AddTemplate("Flags",
            new TemplateMember("A", LogixDataTypes.BOOL),
            new TemplateMember("B", LogixDataTypes.BOOL),
            new TemplateMember("C", LogixDataTypes.BOOL));
        db.AddTag("f1", tpl);
        var root = db.FindByName("f1")!;

        var segs = new CipPathSegment[] { new SymbolicPathSegment("C") };
        var ok = TagPathWalker.TryWalk(root, segs, db.FindTemplate, out var res, out var err);

        Assert.True(ok, err);
        Assert.Equal(0, res.Offset);             // Host byte at struct offset 0.
        Assert.Equal(LogixDataTypes.BOOL, res.TypeCode);
        Assert.Equal(2, res.BitPos);             // C is the third BOOL → bit 2.
    }

    [Fact]
    public void ResolvesRootArrayElement()
    {
        var db = new TagDatabase();
        db.AddTag("arr", LogixDataTypes.DINT, elementCount: 10);
        var root = db.FindByName("arr")!;

        var segs = new CipPathSegment[] { new ElementPathSegment(3) };
        var ok = TagPathWalker.TryWalk(root, segs, db.FindTemplate, out var res, out var err);

        Assert.True(ok, err);
        Assert.Equal(12, res.Offset);
        Assert.Equal(LogixDataTypes.DINT, res.TypeCode);
    }

    [Fact]
    public void ResolvesMemberArrayElement()
    {
        // A template with a member array: SINT Buffer[16] at offset 0.
        var members = new[]
        {
            new TemplateMemberInfo("Buffer", LogixDataTypes.SINT, 0, 16, 1),
        };
        var tpl = new TemplateDefinition(0x300, "Rec", 0x8300, 16, members);
        TemplateDefinition? Templates(ushort id) => id == tpl.InstanceId ? tpl : null;

        var root = new Tag(
            instanceId: 1, name: "r",
            symbolType: LogixDataTypes.MakeStructSymbolType(tpl.InstanceId),
            tagType: tpl.StructureHandle,
            elementSize: (int)tpl.StructureSize);

        var segs = new CipPathSegment[]
        {
            new SymbolicPathSegment("Buffer"),
            new ElementPathSegment(5),
        };

        var ok = TagPathWalker.TryWalk(root, segs, Templates, out var res, out var err);

        Assert.True(ok, err);
        Assert.Equal(5, res.Offset); // 5 SINTs in.
        Assert.Equal(LogixDataTypes.SINT, res.TypeCode);
    }

    [Fact]
    public void FailsOnUnknownMember()
    {
        var db = new TagDatabase();
        var tpl = db.AddTemplate("T", new TemplateMember("A", LogixDataTypes.DINT));
        db.AddTag("t1", tpl);
        var root = db.FindByName("t1")!;

        var segs = new CipPathSegment[] { new SymbolicPathSegment("Missing") };
        var ok = TagPathWalker.TryWalk(root, segs, db.FindTemplate, out _, out var err);

        Assert.False(ok);
        Assert.NotNull(err);
        Assert.Contains("Missing", err);
    }

    [Fact]
    public void FailsOnMemberDrillIntoScalar()
    {
        var db = new TagDatabase();
        db.AddTag("rate", LogixDataTypes.DINT);
        var root = db.FindByName("rate")!;

        var segs = new CipPathSegment[] { new SymbolicPathSegment("SubField") };
        var ok = TagPathWalker.TryWalk(root, segs, db.FindTemplate, out _, out var err);

        Assert.False(ok);
        Assert.NotNull(err);
        Assert.Contains("non-structure", err);
    }

    [Fact]
    public void FailsOnElementIndexBeyondArrayBounds()
    {
        var db = new TagDatabase();
        db.AddTag("arr", LogixDataTypes.DINT, elementCount: 4);
        var root = db.FindByName("arr")!;

        var segs = new CipPathSegment[] { new ElementPathSegment(10) };
        var ok = TagPathWalker.TryWalk(root, segs, db.FindTemplate, out _, out var err);

        Assert.False(ok);
        Assert.Contains("out of range", err);
    }
}
