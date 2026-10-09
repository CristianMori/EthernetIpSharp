using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Unit tests for the provisional LogixStructureHandle helper. Covers only
// what the algorithm can confidently encode today (atomic-only UDTs); for
// everything else, verifies the helper refuses rather than producing a
// plausible-but-unverified handle.
public class LogixStructureHandleTests
{
    [Fact]
    public void TryBuildFormalStrucSpec_ThreeAtomicMembers_MatchesSpecExample()
    {
        // CIP Vol 1 §C-6.1 Example 3: STRUCT ::= { UINT, SINT, INT } encodes
        // as [A2][03][C7][C2][C3]. Build the same UDT via the template API
        // and verify the helper emits those exact bytes.
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Three",
            new TemplateMember("A", LogixDataTypes.UINT),
            new TemplateMember("B", LogixDataTypes.SINT),
            new TemplateMember("C", LogixDataTypes.INT));
        Assert.True(LogixStructureHandle.TryBuildFormalStrucSpec(tpl, out var bytes));
        Assert.Equal(new byte[] { 0xA2, 0x03, 0xC7, 0xC2, 0xC3 }, bytes);
    }

    [Fact]
    public void TryComputeStructureHandle_SpecExample_Produces0x5159()
    {
        // Same vector, through the CRC path.  CipCrc16 of the bytes above
        // is 0x5159 — the value the spec quotes.
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Three",
            new TemplateMember("A", LogixDataTypes.UINT),
            new TemplateMember("B", LogixDataTypes.SINT),
            new TemplateMember("C", LogixDataTypes.INT));
        Assert.True(LogixStructureHandle.TryComputeStructureHandle(tpl, out var handle));
        Assert.Equal(0x5159, handle);
    }

    [Fact]
    public void TryBuildFormalStrucSpec_UnsignedAndBitStringMembers_RoundTrip()
    {
        // All the new §C-6.1 types also encode as a single byte each.
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Mixed",
            new TemplateMember("U32", LogixDataTypes.UDINT),
            new TemplateMember("U8",  LogixDataTypes.USINT),
            new TemplateMember("W",   LogixDataTypes.WORD));
        Assert.True(LogixStructureHandle.TryBuildFormalStrucSpec(tpl, out var bytes));
        Assert.Equal(new byte[] { 0xA2, 0x03, 0xC8, 0xC6, 0xD2 }, bytes);
    }

    [Fact]
    public void TryBuildFormalStrucSpec_WithPackedBool_Refuses()
    {
        // UDTs with packed BOOLs can't be encoded by the simple algorithm
        // yet (needs the FormalHandleStrucTypeSpec variant plus Rockwell's
        // specific handling for hidden host bytes). Must refuse rather
        // than ship a wrong handle.
        var db = new TagDatabase();
        var tpl = db.AddTemplate("WithBool",
            new TemplateMember("A", LogixDataTypes.DINT),
            new TemplateMember("B", LogixDataTypes.BOOL));
        Assert.False(LogixStructureHandle.TryBuildFormalStrucSpec(tpl, out var bytes));
        Assert.Empty(bytes);
    }

    [Fact]
    public void TryBuildFormalStrucSpec_WithArrayMember_Refuses()
    {
        // Arrays need the array-encoding productions; the simple scalar
        // path can't represent them.
        var db = new TagDatabase();
        var tpl = db.AddTemplate("WithArray",
            new TemplateMember("Buffer", LogixDataTypes.SINT, arraySize: 16));
        Assert.False(LogixStructureHandle.TryBuildFormalStrucSpec(tpl, out _));
    }

    [Fact]
    public void TryComputeStructureHandle_NotWiredAsDefault()
    {
        // Explicit guard: AddTemplate still returns 0x8000 | instanceId for
        // its own StructureHandle. The helper is opt-in via
        // AddTemplate(TemplateDefinition) with the caller's handle.
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Three",
            new TemplateMember("A", LogixDataTypes.UINT),
            new TemplateMember("B", LogixDataTypes.SINT),
            new TemplateMember("C", LogixDataTypes.INT));
        Assert.Equal(0x8000 | tpl.InstanceId, tpl.StructureHandle);
    }
}
