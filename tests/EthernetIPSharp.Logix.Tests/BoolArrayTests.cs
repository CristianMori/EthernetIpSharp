using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Tests for gap 6 (BOOL arrays DWORD-packed). Acceptance: BOOL[32] occupies
// 4 bytes; WriteAsync("Flags[5]", true) sets bit 5 of DWORD 0.
public class BoolArrayTests
{
    [Fact]
    public void AddBool32_OccupiesFourBytes()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Flags", LogixDataTypes.BOOL, elementCount: 32);
        Assert.Equal(4, tag.DataSize);
        Assert.Equal(32, tag.ElementCount);
        Assert.Equal(32u, tag.Dims[0]);
    }

    [Fact]
    public void AddBool128_OccupiesSixteenBytes()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Big", LogixDataTypes.BOOL, elementCount: 128);
        Assert.Equal(16, tag.DataSize);
    }

    [Fact]
    public void AddBoolArray_NonMultipleOf32_Throws()
    {
        var db = new TagDatabase();
        var ex = Assert.Throws<ArgumentException>(() =>
            db.AddTag("Bad", LogixDataTypes.BOOL, elementCount: 10));
        Assert.Contains("multiple of 32", ex.Message);
    }

    [Fact]
    public void AddBoolScalar_StillOneByte()
    {
        // A plain BOOL (not an array) still occupies one byte.
        var db = new TagDatabase();
        var tag = db.AddTag("scalar", LogixDataTypes.BOOL);
        Assert.Equal(1, tag.DataSize);
    }

    [Fact]
    public void Walker_BoolArrayIndex_MapsToByteAndBit()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Flags", LogixDataTypes.BOOL, elementCount: 32);

        // Index 5 → byte 0, bit 5.
        var ok = TagPathWalker.TryWalk(tag, new CipPathSegment[]
        {
            new ElementPathSegment(5),
        }, db.FindTemplate, out var r, out var err);

        Assert.True(ok, err);
        Assert.Equal(0, r.Offset);
        Assert.Equal(5, r.BitPos);
        Assert.Equal(LogixDataTypes.BOOL, r.TypeCode);
    }

    [Fact]
    public void Walker_BoolArrayIndex_AcrossDwordBoundary()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Big", LogixDataTypes.BOOL, elementCount: 128);

        // Bit index 65 → byte 8, bit 1.
        var ok = TagPathWalker.TryWalk(tag, new CipPathSegment[]
        {
            new ElementPathSegment(65),
        }, db.FindTemplate, out var r, out _);

        Assert.True(ok);
        Assert.Equal(8, r.Offset);
        Assert.Equal(1, r.BitPos);
    }

    [Fact]
    public void Dispatcher_WriteFlagsBit5_SetsBit5OfByte0()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Flags", LogixDataTypes.BOOL, elementCount: 32);
        var logix = new LogixDispatcher(db);

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("Flags"),
                new ElementPathSegment(5),
            },
        };
        var write = new byte[5];
        BinaryPrimitives.WriteUInt16LittleEndian(write, LogixDataTypes.BOOL);
        BinaryPrimitives.WriteUInt16LittleEndian(write.AsSpan(2), 1);
        write[4] = 1;

        var resp = logix.Dispatch(TagServices.WriteTag, path, write);

        Assert.True(resp.Status.IsSuccess, $"status=0x{resp.Status.GeneralStatus:X2}");
        Assert.Equal(0b_0010_0000, tag.Read<byte>(0)); // bit 5 = 0x20
        Assert.Equal(0, tag.Read<byte>(1)); // neighbors untouched
    }

    [Fact]
    public void Dispatcher_ReadFlagsBit_ReturnsSingleBit()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Flags", LogixDataTypes.BOOL, elementCount: 32);
        tag.Write<byte>(1, 0b_0000_0100); // Set bit 2 of byte 1 (bit index 10).
        var logix = new LogixDispatcher(db);

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("Flags"),
                new ElementPathSegment(10),
            },
        };
        var req = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(req, 1);

        var resp = logix.Dispatch(TagServices.ReadTag, path, req);

        Assert.True(resp.Status.IsSuccess);
        var span = resp.Data.Span;
        Assert.Equal(LogixDataTypes.BOOL, BinaryPrimitives.ReadUInt16LittleEndian(span));
        Assert.Equal(1, span[2]);
    }

    [Fact]
    public void Dispatcher_ReadFlagsBit_ReturnsZeroWhenClear()
    {
        var db = new TagDatabase();
        db.AddTag("Flags", LogixDataTypes.BOOL, elementCount: 32);
        var logix = new LogixDispatcher(db);

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("Flags"),
                new ElementPathSegment(7),
            },
        };
        var req = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(req, 1);

        var resp = logix.Dispatch(TagServices.ReadTag, path, req);

        Assert.True(resp.Status.IsSuccess);
        Assert.Equal(0, resp.Data.Span[2]);
    }
}
