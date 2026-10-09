using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Tests for gap 3 (nested-struct layout in the simple AddTemplate path + the
// pre-resolved AddTemplate(TemplateDefinition) overload the transpiler will use).
public class TemplateRegistrationTests
{
    [Fact]
    public void SimpleAddTemplate_NestedStructMember_UsesNestedStructureSize()
    {
        var db = new TagDatabase();
        var timerTpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        // A nested-struct member references the child template via its structure
        // handle (0x8000 | childInstanceId).
        var motorTpl = db.AddTemplate("Motor",
            new TemplateMember("Speed", LogixDataTypes.REAL),
            new TemplateMember("Timer", timerTpl.StructureHandle));

        // Motor { Speed:REAL @0, Timer @4 (size 8) } → StructureSize = 12
        Assert.Equal(12u, motorTpl.StructureSize);

        // Timer member must carry the 0x8000 bit so clients recurse via Template_Read.
        var timerMember = motorTpl.Members.First(m => m.Name == "Timer");
        Assert.True((timerMember.DataType & 0x8000) != 0);
        Assert.Equal(timerTpl.InstanceId, LogixDataTypes.GetTemplateId(timerMember.DataType));
        Assert.Equal(4, timerMember.Offset);
        Assert.Equal((int)timerTpl.StructureSize, timerMember.ElementSize);
    }

    [Fact]
    public void SimpleAddTemplate_UnregisteredNestedTemplate_Throws()
    {
        var db = new TagDatabase();
        // 0x8ABC references a template id that hasn't been registered — should throw
        // rather than silently fall back to 4 bytes and produce garbage layout.
        var ex = Assert.Throws<InvalidOperationException>(() =>
            db.AddTemplate("Bad", new TemplateMember("Child", 0x8ABC)));
        Assert.Contains("unregistered nested template", ex.Message);
    }

    [Fact]
    public void PreResolvedAddTemplate_RegistersLayoutVerbatim()
    {
        var db = new TagDatabase();

        // Transpiler-style: caller supplies exact offsets and sizes derived from an L5X.
        // Simulates a Logix STRING structure (LEN @0, DATA[82] @4, 88 bytes total).
        var members = new[]
        {
            new TemplateMemberInfo("LEN", LogixDataTypes.DINT, 0, 0, 4),
            new TemplateMemberInfo("DATA", LogixDataTypes.SINT, 4, 82, 1),
        };
        var stringTpl = new TemplateDefinition(
            instanceId: 0x500,
            name: "STRING",
            structureHandle: 0xE500, // Logix uses CRC; we're free to pick.
            structureSize: 88,
            members: members);

        var returned = db.AddTemplate(stringTpl);

        Assert.Same(stringTpl, returned);
        var found = db.FindTemplate(0x500);
        Assert.Same(stringTpl, found);
        Assert.Equal(88u, found!.StructureSize);
        Assert.Equal(0xE500, found.StructureHandle);
    }

    [Fact]
    public void PreResolvedAddTemplate_DuplicateInstanceId_Throws()
    {
        var db = new TagDatabase();
        var m = new[] { new TemplateMemberInfo("X", LogixDataTypes.DINT, 0, 0, 4) };
        db.AddTemplate(new TemplateDefinition(0x600, "T", 0x8600, 4, m));

        var ex = Assert.Throws<InvalidOperationException>(() =>
            db.AddTemplate(new TemplateDefinition(0x600, "Other", 0x8600, 4, m)));
        Assert.Contains("0x0600", ex.Message);
    }

    [Fact]
    public void PreResolvedAddTemplate_ZeroInstanceId_Throws()
    {
        var db = new TagDatabase();
        var m = new[] { new TemplateMemberInfo("X", LogixDataTypes.DINT, 0, 0, 4) };
        var ex = Assert.Throws<ArgumentException>(() =>
            db.AddTemplate(new TemplateDefinition(0, "T", 0x8000, 4, m)));
        Assert.Contains("InstanceId", ex.Message);
    }

    [Fact]
    public void PreResolvedAddTemplate_BumpsAutoAssignCounter()
    {
        var db = new TagDatabase();
        // Register a pre-resolved template at a high id — the counter should advance
        // past it so the next auto-assigned template doesn't collide.
        var m = new[] { new TemplateMemberInfo("X", LogixDataTypes.DINT, 0, 0, 4) };
        db.AddTemplate(new TemplateDefinition(0x800, "Pre", 0x8800, 4, m));

        var autoAssigned = db.AddTemplate("Auto", new TemplateMember("X", LogixDataTypes.DINT));

        Assert.True(autoAssigned.InstanceId > 0x800,
            $"expected id past 0x800, got 0x{autoAssigned.InstanceId:X}");
    }

    [Fact]
    public void NestedStruct_MemberDrill_ThroughWalker()
    {
        // End-to-end: register Timer, register Motor {Speed, Timer}, add a Motor tag,
        // read Motor.Timer.PRE via the dispatcher. Proves the nested-struct fix is
        // discoverable through the CIP path (the walker needs member.DataType to
        // carry the 0x8000 bit — set by the AddTemplate fix).
        var db = new TagDatabase();
        var timerTpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        var motorTpl = db.AddTemplate("Motor",
            new TemplateMember("Speed", LogixDataTypes.REAL),
            new TemplateMember("Timer", timerTpl.StructureHandle));
        var tag = db.AddTag("m1", motorTpl);
        // Motor bytes: Speed @0..4, Timer @4..12 (PRE @4..8, ACC @8..12)
        tag.Write<int>(4, 987654);

        var logix = new LogixDispatcher(db);
        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("m1"),
                new SymbolicPathSegment("Timer"),
                new SymbolicPathSegment("PRE"),
            },
        };
        var req = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(req, 1);

        var resp = logix.Dispatch(TagServices.ReadTag, path, req);

        Assert.True(resp.Status.IsSuccess, $"status=0x{resp.Status.GeneralStatus:X2}");
        var span = resp.Data.Span;
        Assert.Equal(LogixDataTypes.DINT, BinaryPrimitives.ReadUInt16LittleEndian(span));
        Assert.Equal(987654, BinaryPrimitives.ReadInt32LittleEndian(span.Slice(2)));
    }
}
