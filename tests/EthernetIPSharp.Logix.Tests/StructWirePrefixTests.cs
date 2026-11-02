using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

/// <summary>
/// Regression tests for issue #2: Logix structured-tag reads and writes must
/// use the [0x02A0][structure_handle] wire prefix (CIP Vol 1 §C-4.4.5), not
/// the 2-byte atomic type code. libplctag and pycomm3 both enforce this split.
/// Covers the whole-tag path and the walker-aware path, plus negative cases
/// that confirm atomic behavior is unchanged.
/// </summary>
public class StructWirePrefixTests
{
    private const ushort StructTypeIndicator = 0x02A0;

    // ---------- Whole-tag path ----------

    [Fact]
    public void HandleReadTag_Struct_EmitsFourByteStructPrefix()
    {
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        db.AddTag("t1", tpl);
        var tag = db.FindByName("t1")!;

        // Write some data into the tag so we can verify it round-trips.
        tag.Write(0, 123);           // PRE
        tag.Write(4, 456);           // ACC

        var response = TagServices.HandleReadTag(tag, TagServices.ReadTag, new byte[] { 0x01, 0x00 });

        Assert.True(response.Status.IsSuccess);
        var data = response.Data.ToArray();

        // Prefix layout: [0x02A0 LE][structure_handle LE][struct_bytes...]
        Assert.Equal(4 + (int)tpl.StructureSize, data.Length);
        Assert.Equal(StructTypeIndicator, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(tpl.StructureHandle, BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2)));
        Assert.Equal(123, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4)));
        Assert.Equal(456, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(8)));
    }

    [Fact]
    public void HandleReadTag_Atomic_StaysTwoBytePrefix()
    {
        // Atomic path must be untouched — regression guard against breaking
        // libplctag / pycomm3 scalar reads.
        var tag = new Tag(1, "rate",
            LogixDataTypes.MakeAtomicSymbolType(LogixDataTypes.DINT),
            LogixDataTypes.DINT, elementSize: 4);
        tag.Write(0, 42);

        var response = TagServices.HandleReadTag(tag, TagServices.ReadTag, new byte[] { 0x01, 0x00 });

        Assert.True(response.Status.IsSuccess);
        var data = response.Data.ToArray();
        Assert.Equal(6, data.Length);
        Assert.Equal(LogixDataTypes.DINT, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(42, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(2)));
    }

    [Fact]
    public void HandleWriteTag_Struct_AcceptsSixByteHeader_Succeeds()
    {
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        db.AddTag("t1", tpl);
        var tag = db.FindByName("t1")!;

        // [0x02A0][struct_handle][count=1][PRE=777][ACC=888]
        var req = new byte[6 + (int)tpl.StructureSize];
        BinaryPrimitives.WriteUInt16LittleEndian(req, StructTypeIndicator);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), tpl.StructureHandle);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(4), 1);
        BinaryPrimitives.WriteInt32LittleEndian(req.AsSpan(6), 777);
        BinaryPrimitives.WriteInt32LittleEndian(req.AsSpan(10), 888);

        var response = TagServices.HandleWriteTag(tag, TagServices.WriteTag, req);

        Assert.True(response.Status.IsSuccess);
        Assert.Equal(777, BinaryPrimitives.ReadInt32LittleEndian(tag.GetData().Slice(0, 4)));
        Assert.Equal(888, BinaryPrimitives.ReadInt32LittleEndian(tag.GetData().Slice(4, 4)));
    }

    [Fact]
    public void HandleWriteTag_Struct_WrongIndicator_Rejected()
    {
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT));
        db.AddTag("t1", tpl);
        var tag = db.FindByName("t1")!;

        var req = new byte[6 + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(req, 0x1234);       // Wrong indicator
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), tpl.StructureHandle);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(4), 1);

        var response = TagServices.HandleWriteTag(tag, TagServices.WriteTag, req);

        Assert.Equal(0xFF, response.Status.GeneralStatus);
        Assert.Contains((ushort)0x2107, response.Status.AdditionalStatus);
    }

    [Fact]
    public void HandleWriteTag_Struct_WrongHandle_Rejected()
    {
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT));
        db.AddTag("t1", tpl);
        var tag = db.FindByName("t1")!;

        var req = new byte[6 + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(req, StructTypeIndicator);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), (ushort)(tpl.StructureHandle ^ 0xFFFF));
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(4), 1);

        var response = TagServices.HandleWriteTag(tag, TagServices.WriteTag, req);

        Assert.Equal(0xFF, response.Status.GeneralStatus);
        Assert.Contains((ushort)0x2107, response.Status.AdditionalStatus);
    }

    [Fact]
    public void HandleWriteTag_Atomic_StillAcceptsFourByteHeader()
    {
        // Regression guard: atomic writes continue to use the 4-byte header
        // [type][count][data], never the struct 6-byte form.
        var tag = new Tag(1, "rate",
            LogixDataTypes.MakeAtomicSymbolType(LogixDataTypes.DINT),
            LogixDataTypes.DINT, elementSize: 4);

        var req = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(req, LogixDataTypes.DINT);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), 1);
        BinaryPrimitives.WriteInt32LittleEndian(req.AsSpan(4), 99);

        var response = TagServices.HandleWriteTag(tag, TagServices.WriteTag, req);

        Assert.True(response.Status.IsSuccess);
        Assert.Equal(99, tag.Read<int>());
    }

    [Fact]
    public void HandleReadTagFragmented_Struct_EmitsFourBytePrefix()
    {
        // Build a struct bigger than MaxReplyData (480) so the first fragment
        // is forced to be partial. 8-DINT template = 32 bytes/instance; need
        // ≥121 instances to pass the fit-check — simplest is to make a single
        // large structure via a long member list.
        var db = new TagDatabase();
        var builder = new List<TemplateMember>();
        for (int i = 0; i < 130; i++) builder.Add(new TemplateMember($"m{i}", LogixDataTypes.DINT));
        var tpl = db.AddTemplate("BigUdt", builder.ToArray());
        db.AddTag("big", tpl);
        var tag = db.FindByName("big")!;

        // Read fragmented: [count=1][offset=0]
        var req = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(req, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(req.AsSpan(2), 0);

        var response = TagServices.HandleReadTagFragmented(tag, TagServices.ReadTagFragmented, req);

        var data = response.Data.ToArray();
        Assert.Equal(StructTypeIndicator, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(tpl.StructureHandle, BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2)));
        // Partial transfer status (0x06) with 0x80 service bit set.
        Assert.Equal((byte)(TagServices.ReadTagFragmented | 0x80), response.ServiceCode);
        Assert.Equal(0x06, response.Status.GeneralStatus);
    }

    [Fact]
    public void HandleWriteTagFragmented_Struct_AcceptsTenByteHeader()
    {
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        db.AddTag("t1", tpl);
        var tag = db.FindByName("t1")!;

        // Fragmented write: [0x02A0][handle][count=1][offset=4][write ACC=321]
        var req = new byte[14];
        BinaryPrimitives.WriteUInt16LittleEndian(req, StructTypeIndicator);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), tpl.StructureHandle);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(req.AsSpan(6), 4);
        BinaryPrimitives.WriteInt32LittleEndian(req.AsSpan(10), 321);

        var response = TagServices.HandleWriteTagFragmented(tag, TagServices.WriteTagFragmented, req);

        Assert.True(response.Status.IsSuccess);
        Assert.Equal(321, BinaryPrimitives.ReadInt32LittleEndian(tag.GetData().Slice(4, 4)));
    }

    // ---------- Walker-aware path (member drilling) ----------

    [Fact]
    public void HandleReadTagAt_StructMember_EmitsFourBytePrefix()
    {
        // Build Motor { Speed:REAL, Timer:Timer } with Timer a registered template.
        var db = new TagDatabase();
        var timerTpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));

        var motorMembers = new[]
        {
            new TemplateMemberInfo("Speed", LogixDataTypes.REAL, 0, 0, 4),
            new TemplateMemberInfo("Timer", (ushort)(0x8000 | timerTpl.InstanceId), 4, 0, (int)timerTpl.StructureSize),
        };
        var motorTpl = new TemplateDefinition(
            instanceId: 0x301, name: "Motor",
            structureHandle: 0xBEEF,
            structureSize: 4 + timerTpl.StructureSize,
            members: motorMembers);

        TemplateDefinition? LookupTpl(ushort id) =>
            id == timerTpl.InstanceId ? timerTpl :
            id == motorTpl.InstanceId ? motorTpl : null;

        var tag = new Tag(
            instanceId: 100, name: "m1",
            symbolType: LogixDataTypes.MakeStructSymbolType(motorTpl.InstanceId),
            tagType: motorTpl.StructureHandle,
            elementSize: (int)motorTpl.StructureSize);
        tag.Write(4, 11);   // Timer.PRE
        tag.Write(8, 22);   // Timer.ACC

        var segs = new CipPathSegment[] { new SymbolicPathSegment("Timer") };
        Assert.True(TagPathWalker.TryWalk(tag, segs, LookupTpl, out var walked, out _));

        var response = TagServices.HandleReadTagAt(tag, TagServices.ReadTag, new byte[] { 0x01, 0x00 }, walked);

        Assert.True(response.Status.IsSuccess);
        var data = response.Data.ToArray();
        // Expect: [0x02A0][Timer.StructureHandle][PRE=11][ACC=22]
        Assert.Equal(4 + (int)timerTpl.StructureSize, data.Length);
        Assert.Equal(StructTypeIndicator, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(timerTpl.StructureHandle, BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2)));
        Assert.Equal(11, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4)));
        Assert.Equal(22, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(8)));
    }

    [Fact]
    public void HandleReadTagAt_AtomicMember_StaysTwoBytePrefix()
    {
        // Walker ending on an atomic member must still emit the 2-byte prefix.
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        db.AddTag("t1", tpl);
        var tag = db.FindByName("t1")!;
        tag.Write(4, 777); // ACC

        var segs = new CipPathSegment[] { new SymbolicPathSegment("ACC") };
        Assert.True(TagPathWalker.TryWalk(tag, segs, db.FindTemplate, out var walked, out _));

        var response = TagServices.HandleReadTagAt(tag, TagServices.ReadTag, new byte[] { 0x01, 0x00 }, walked);

        Assert.True(response.Status.IsSuccess);
        var data = response.Data.ToArray();
        Assert.Equal(6, data.Length); // 2-byte prefix + 4-byte DINT
        Assert.Equal(LogixDataTypes.DINT, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(777, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(2)));
    }

    [Fact]
    public void HandleWriteTagAt_StructMember_AcceptsSixByteHeader()
    {
        var db = new TagDatabase();
        var timerTpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));

        var motorMembers = new[]
        {
            new TemplateMemberInfo("Speed", LogixDataTypes.REAL, 0, 0, 4),
            new TemplateMemberInfo("Timer", (ushort)(0x8000 | timerTpl.InstanceId), 4, 0, (int)timerTpl.StructureSize),
        };
        var motorTpl = new TemplateDefinition(
            instanceId: 0x301, name: "Motor",
            structureHandle: 0xBEEF,
            structureSize: 4 + timerTpl.StructureSize,
            members: motorMembers);

        TemplateDefinition? LookupTpl(ushort id) =>
            id == timerTpl.InstanceId ? timerTpl :
            id == motorTpl.InstanceId ? motorTpl : null;

        var tag = new Tag(
            instanceId: 100, name: "m1",
            symbolType: LogixDataTypes.MakeStructSymbolType(motorTpl.InstanceId),
            tagType: motorTpl.StructureHandle,
            elementSize: (int)motorTpl.StructureSize);

        var segs = new CipPathSegment[] { new SymbolicPathSegment("Timer") };
        Assert.True(TagPathWalker.TryWalk(tag, segs, LookupTpl, out var walked, out _));

        var req = new byte[6 + (int)timerTpl.StructureSize];
        BinaryPrimitives.WriteUInt16LittleEndian(req, StructTypeIndicator);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), timerTpl.StructureHandle);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(4), 1);
        BinaryPrimitives.WriteInt32LittleEndian(req.AsSpan(6), 555);
        BinaryPrimitives.WriteInt32LittleEndian(req.AsSpan(10), 666);

        var response = TagServices.HandleWriteTagAt(tag, TagServices.WriteTag, req, walked);

        Assert.True(response.Status.IsSuccess);
        Assert.Equal(555, BinaryPrimitives.ReadInt32LittleEndian(tag.GetData().Slice(4, 4)));
        Assert.Equal(666, BinaryPrimitives.ReadInt32LittleEndian(tag.GetData().Slice(8, 4)));
    }

    [Fact]
    public void HandleWriteTagAt_StructMember_WrongHandle_Rejected()
    {
        var db = new TagDatabase();
        var timerTpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT));

        var motorMembers = new[]
        {
            new TemplateMemberInfo("Timer", (ushort)(0x8000 | timerTpl.InstanceId), 0, 0, (int)timerTpl.StructureSize),
        };
        var motorTpl = new TemplateDefinition(
            instanceId: 0x301, name: "Motor",
            structureHandle: 0xBEEF,
            structureSize: timerTpl.StructureSize,
            members: motorMembers);

        TemplateDefinition? LookupTpl(ushort id) =>
            id == timerTpl.InstanceId ? timerTpl :
            id == motorTpl.InstanceId ? motorTpl : null;

        var tag = new Tag(
            instanceId: 100, name: "m1",
            symbolType: LogixDataTypes.MakeStructSymbolType(motorTpl.InstanceId),
            tagType: motorTpl.StructureHandle,
            elementSize: (int)motorTpl.StructureSize);

        var segs = new CipPathSegment[] { new SymbolicPathSegment("Timer") };
        Assert.True(TagPathWalker.TryWalk(tag, segs, LookupTpl, out var walked, out _));

        var req = new byte[6 + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(req, StructTypeIndicator);
        // Wrong handle — must be rejected with 0xFF/0x2107.
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), (ushort)(timerTpl.StructureHandle ^ 0xFFFF));
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(4), 1);

        var response = TagServices.HandleWriteTagAt(tag, TagServices.WriteTag, req, walked);

        Assert.Equal(0xFF, response.Status.GeneralStatus);
        Assert.Contains((ushort)0x2107, response.Status.AdditionalStatus);
    }
}
