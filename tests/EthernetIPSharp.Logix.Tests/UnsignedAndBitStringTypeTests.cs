using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Tests for the full CIP elementary type family on the Logix tag server:
// signed/unsigned 8..64-bit integers plus the bit-string family
// (BYTE/WORD/DWORD/LWORD).  CIP Vol 1 §C-6.1 defines all of these; prior to
// this change the Logix side only knew the signed integers + REAL/LREAL +
// DWORD, so AddTag threw ArgumentException on UDINT (which EscaFlow needs).
public class UnsignedAndBitStringTypeTests
{
    public static TheoryData<ushort, int> AtomicTypeSizes() => new()
    {
        { LogixDataTypes.SINT,  1 },
        { LogixDataTypes.USINT, 1 },
        { LogixDataTypes.BYTE,  1 },
        { LogixDataTypes.INT,   2 },
        { LogixDataTypes.UINT,  2 },
        { LogixDataTypes.WORD,  2 },
        { LogixDataTypes.DINT,  4 },
        { LogixDataTypes.UDINT, 4 },
        { LogixDataTypes.DWORD, 4 },
        { LogixDataTypes.REAL,  4 },
        { LogixDataTypes.LINT,  8 },
        { LogixDataTypes.ULINT, 8 },
        { LogixDataTypes.LWORD, 8 },
        { LogixDataTypes.LREAL, 8 },
    };

    [Theory]
    [MemberData(nameof(AtomicTypeSizes))]
    public void GetElementSize_ReturnsSpecDefinedSize(ushort code, int expected)
    {
        Assert.Equal(expected, LogixDataTypes.GetElementSize(code));
    }

    [Fact]
    public void AddTag_UdintScalar_SucceedsAndAcceptsFullRange()
    {
        // The specific crash reported by EscaFlow: Unknown tag type 0x00C8.
        var db = new TagDatabase();
        var tag = db.AddTag("counter", LogixDataTypes.UDINT);
        Assert.Equal(4, tag.ElementSize);
        Assert.Equal(4, tag.DataSize);

        // Full unsigned 32-bit range must round-trip without sign-extension.
        tag.Write<uint>(0, 0xFFFF_FFFFu);
        Assert.Equal(0xFFFF_FFFFu, tag.Read<uint>(0));
        // Reading as signed exposes the two's-complement — that's expected
        // (the bytes are the bytes), but we never want silent truncation.
        Assert.Equal(-1, tag.Read<int>(0));
    }

    [Theory]
    [InlineData(LogixDataTypes.USINT, (ulong)byte.MaxValue)]
    [InlineData(LogixDataTypes.UINT,  (ulong)ushort.MaxValue)]
    [InlineData(LogixDataTypes.UDINT, (ulong)uint.MaxValue)]
    [InlineData(LogixDataTypes.ULINT, ulong.MaxValue)]
    public void UnsignedBoundaryWritesAreNotSignExtended(ushort code, ulong max)
    {
        var db = new TagDatabase();
        var tag = db.AddTag("x", code);
        var bytes = BitConverter.GetBytes(max);
        tag.SetData(bytes.AsSpan(0, tag.ElementSize));
        // Readback as unsigned must preserve the full value.
        ulong actual = tag.ElementSize switch
        {
            1 => tag.Read<byte>(0),
            2 => tag.Read<ushort>(0),
            4 => tag.Read<uint>(0),
            8 => tag.Read<ulong>(0),
            _ => throw new InvalidOperationException(),
        };
        Assert.Equal(max, actual);
    }

    [Theory]
    [InlineData(LogixDataTypes.BYTE,  1)]
    [InlineData(LogixDataTypes.WORD,  2)]
    [InlineData(LogixDataTypes.LWORD, 8)]
    public void BitStringTypesAllocateCorrectWidth(ushort code, int expectedSize)
    {
        var db = new TagDatabase();
        var tag = db.AddTag("bits", code);
        Assert.Equal(expectedSize, tag.DataSize);
    }

    [Fact]
    public void AddArray_OfUdint_AllocatesN_x_4Bytes()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("counters", LogixDataTypes.UDINT, elementCount: 16);
        Assert.Equal(16 * 4, tag.DataSize);
        tag.Write<uint>(15 * 4, 0xDEAD_BEEFu);
        Assert.Equal(0xDEAD_BEEFu, tag.Read<uint>(15 * 4));
    }

    [Fact]
    public void UdtMember_WithEveryNewType_ComputesCorrectLayout()
    {
        // Verifies the template layout math works with the full unsigned +
        // bit-string family (alignment and size pulled from the same table).
        var db = new TagDatabase();
        var tpl = db.AddTemplate("All",
            new TemplateMember("U8",   LogixDataTypes.USINT),
            new TemplateMember("U16",  LogixDataTypes.UINT),
            new TemplateMember("U32",  LogixDataTypes.UDINT),
            new TemplateMember("U64",  LogixDataTypes.ULINT),
            new TemplateMember("B8",   LogixDataTypes.BYTE),
            new TemplateMember("W16",  LogixDataTypes.WORD),
            new TemplateMember("LW64", LogixDataTypes.LWORD));

        // Expected packed layout respecting Logix alignment:
        //   U8   @ 0      (align 1)
        //   U16  @ 2      (align 2)
        //   U32  @ 4      (align 4)
        //   U64  @ 8      (align 8)
        //   B8   @ 16     (align 1)
        //   W16  @ 18     (align 2)
        //   LW64 @ 24     (align 8)   total 32 (already 4-aligned)
        var members = tpl.Members.ToList();
        Assert.Equal(0,  members.Single(m => m.Name == "U8").Offset);
        Assert.Equal(2,  members.Single(m => m.Name == "U16").Offset);
        Assert.Equal(4,  members.Single(m => m.Name == "U32").Offset);
        Assert.Equal(8,  members.Single(m => m.Name == "U64").Offset);
        Assert.Equal(16, members.Single(m => m.Name == "B8").Offset);
        Assert.Equal(18, members.Single(m => m.Name == "W16").Offset);
        Assert.Equal(24, members.Single(m => m.Name == "LW64").Offset);
        Assert.Equal(32u, tpl.StructureSize);
    }

    [Fact]
    public void Persistence_RoundTripsUnsignedAndBitStringTags()
    {
        var db = new TagDatabase();
        db.AddTag("u8",  LogixDataTypes.USINT).Write<byte>(0, 0xAB);
        db.AddTag("u16", LogixDataTypes.UINT).Write<ushort>(0, 0xBEEF);
        db.AddTag("u32", LogixDataTypes.UDINT).Write<uint>(0, 0xDEAD_BEEFu);
        db.AddTag("u64", LogixDataTypes.ULINT).Write<ulong>(0, 0xFEEDFACE_CAFEBABEuL);
        db.AddTag("b8",  LogixDataTypes.BYTE).Write<byte>(0, 0xFF);
        db.AddTag("w16", LogixDataTypes.WORD).Write<ushort>(0, 0xFFFE);
        db.AddTag("lw64",LogixDataTypes.LWORD).Write<ulong>(0, 0x1122334455667788uL);

        using var ms = new MemoryStream();
        TagDatabasePersistence.Save(db, ms);

        var db2 = new TagDatabase();
        db2.AddTag("u8",  LogixDataTypes.USINT);
        db2.AddTag("u16", LogixDataTypes.UINT);
        db2.AddTag("u32", LogixDataTypes.UDINT);
        db2.AddTag("u64", LogixDataTypes.ULINT);
        db2.AddTag("b8",  LogixDataTypes.BYTE);
        db2.AddTag("w16", LogixDataTypes.WORD);
        db2.AddTag("lw64",LogixDataTypes.LWORD);

        ms.Position = 0;
        var result = TagDatabasePersistence.Load(db2, ms);
        Assert.Equal(7, result.TagsRestored);
        Assert.Equal(0, result.TagsSkipped);

        Assert.Equal(0xAB,                      db2.FindByName("u8")!.Read<byte>(0));
        Assert.Equal(0xBEEF,                    db2.FindByName("u16")!.Read<ushort>(0));
        Assert.Equal(0xDEAD_BEEFu,              db2.FindByName("u32")!.Read<uint>(0));
        Assert.Equal(0xFEEDFACE_CAFEBABEuL,     db2.FindByName("u64")!.Read<ulong>(0));
        Assert.Equal(0xFF,                      db2.FindByName("b8")!.Read<byte>(0));
        Assert.Equal(0xFFFE,                    db2.FindByName("w16")!.Read<ushort>(0));
        Assert.Equal(0x1122334455667788uL,      db2.FindByName("lw64")!.Read<ulong>(0));
    }

    [Fact]
    public void Dispatcher_WriteUdintTag_AcceptsUdintTypeCode()
    {
        // End-to-end through the CIP dispatcher: writing with the UDINT type
        // code (0x00C8) against a UDINT-registered tag must succeed and the
        // bytes must land verbatim (no sign re-interpretation).
        var db = new TagDatabase();
        var tag = db.AddTag("counter", LogixDataTypes.UDINT);
        var logix = new LogixDispatcher(db);

        var path = new CipPath { SymbolicName = "counter" };
        var write = new byte[4 + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(write, LogixDataTypes.UDINT);
        BinaryPrimitives.WriteUInt16LittleEndian(write.AsSpan(2), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(write.AsSpan(4), 0xFFFF_FFFFu);

        var resp = logix.Dispatch(TagServices.WriteTag, path, write);
        Assert.True(resp.Status.IsSuccess, $"status=0x{resp.Status.GeneralStatus:X2}");
        Assert.Equal(0xFFFF_FFFFu, tag.Read<uint>(0));
    }
}
