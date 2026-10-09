using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Tests for gap 5 (multi-dimensional arrays). Acceptance: DINT[5,10,2] and
// friends land at row-major byte offsets and the Symbol Object attribute 8
// reports the correct three UDINTs.
public class MultiDimensionalTests
{
    [Fact]
    public void AddTag_TwoDims_AllocatesRowMajorBuffer()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("m", LogixDataTypes.DINT, new uint[] { 5, 10 });

        Assert.Equal(new uint[] { 5, 10 }, tag.Dims);
        Assert.Equal(50, tag.ElementCount);
        Assert.Equal(200, tag.DataSize); // 50 * 4
    }

    [Fact]
    public void AddTag_ThreeDims_AllocatesRowMajorBuffer()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("m", LogixDataTypes.DINT, new uint[] { 5, 10, 2 });

        Assert.Equal(100, tag.ElementCount);
        Assert.Equal(400, tag.DataSize);
    }

    [Fact]
    public void AddTag_TooManyDims_Throws()
    {
        var db = new TagDatabase();
        Assert.Throws<ArgumentException>(() =>
            db.AddTag("m", LogixDataTypes.DINT, new uint[] { 2, 2, 2, 2 }));
        Assert.Throws<ArgumentException>(() =>
            db.AddTag("m", LogixDataTypes.DINT, Array.Empty<uint>()));
    }

    [Fact]
    public void Walker_ThreeDIndex_ComputesRowMajorOffset()
    {
        // Row-major indexing on DINT[5,10,4] with [1,2,3]:
        //   linear = ((1*10 + 2)*4 + 3) = 51; byte offset = 51*4 = 204.
        // (The requirements-doc example named DINT[5,10,2] with index [1,2,3],
        // but i2=3 is out of range for D2=2 — an internal typo in that doc.
        // Kept the doc's index shape here; picked a compatible D2 instead.)
        var db = new TagDatabase();
        var tag = db.AddTag("Matrix", LogixDataTypes.DINT, new uint[] { 5, 10, 4 });
        tag.Write<int>(204, 7);

        var walked = TagPathWalker.TryWalk(tag, new CipPathSegment[]
        {
            new ElementPathSegment(1),
            new ElementPathSegment(2),
            new ElementPathSegment(3),
        }, db.FindTemplate, out var result, out var err);

        Assert.True(walked, err);
        Assert.Equal(204, result.Offset);
    }

    [Fact]
    public void Walker_UnderIndexed_Errors()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Matrix", LogixDataTypes.DINT, new uint[] { 5, 10, 4 });

        // Only two of three indices supplied — walker must refuse rather than
        // interpret the partial index as pointing at some intermediate slab.
        var ok = TagPathWalker.TryWalk(tag, new CipPathSegment[]
        {
            new ElementPathSegment(1),
            new ElementPathSegment(2),
        }, db.FindTemplate, out _, out var err);

        Assert.False(ok);
        Assert.Contains("Under-indexed", err);
    }

    [Fact]
    public void Walker_IndexOutOfRange_ErrorsWithDimName()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Matrix", LogixDataTypes.DINT, new uint[] { 5, 10, 4 });

        // Dim 1 has size 10, index 999 is beyond it.
        var ok = TagPathWalker.TryWalk(tag, new CipPathSegment[]
        {
            new ElementPathSegment(0),
            new ElementPathSegment(999),
            new ElementPathSegment(0),
        }, db.FindTemplate, out _, out var err);

        Assert.False(ok);
        Assert.Contains("dim 1", err);
    }

    [Fact]
    public void Dispatcher_MultiDimRead_ReturnsCorrectValue()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Matrix", LogixDataTypes.DINT, new uint[] { 5, 10, 4 });
        tag.Write<int>(204, 999);
        var logix = new LogixDispatcher(db);

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("Matrix"),
                new ElementPathSegment(1),
                new ElementPathSegment(2),
                new ElementPathSegment(3),
            },
        };
        var req = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(req, 1);

        var resp = logix.Dispatch(TagServices.ReadTag, path, req);

        Assert.True(resp.Status.IsSuccess, $"status=0x{resp.Status.GeneralStatus:X2}");
        Assert.Equal(999, BinaryPrimitives.ReadInt32LittleEndian(resp.Data.Span.Slice(2)));
    }

    [Fact]
    public void Dispatcher_MultiDimWrite_UpdatesCorrectElement()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("Matrix", LogixDataTypes.DINT, new uint[] { 5, 10, 4 });
        var logix = new LogixDispatcher(db);

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("Matrix"),
                new ElementPathSegment(1),
                new ElementPathSegment(2),
                new ElementPathSegment(3),
            },
        };
        var write = new byte[4 + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(write, LogixDataTypes.DINT);
        BinaryPrimitives.WriteUInt16LittleEndian(write.AsSpan(2), 1);
        BinaryPrimitives.WriteInt32LittleEndian(write.AsSpan(4), 7);

        var resp = logix.Dispatch(TagServices.WriteTag, path, write);

        Assert.True(resp.Status.IsSuccess);
        Assert.Equal(7, tag.Read<int>(204));
        // Neighbors untouched.
        Assert.Equal(0, tag.Read<int>(200));
        Assert.Equal(0, tag.Read<int>(208));
    }

    [Fact]
    public void SymbolObject_Attr8_EmitsAllThreeDims()
    {
        var db = new TagDatabase();
        db.AddTag("Matrix", LogixDataTypes.DINT, new uint[] { 5, 10, 4 });
        var logix = new LogixDispatcher(db);

        // Get_Instance_Attribute_List asking for attr 8.
        var reqData = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(reqData, 1);
        BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(2), 8);

        var path = new CipPath { ClassId = 0x6B, InstanceId = 0 };
        var resp = logix.Dispatch(0x55, path, reqData);
        Assert.True(resp.Status.IsSuccess);

        var span = resp.Data.Span;
        // Per-tag record: UDINT instance_id + 3xUDINT dims.
        int off = 4; // skip instance id
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(off)));
        Assert.Equal(10u, BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(off + 4)));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(off + 8)));
    }

    [Fact]
    public void SingleDim_Overload_StillWorks()
    {
        // Back-compat: the elementCount overload should keep behaving as before,
        // producing a 1-D array with a single-entry Dims list.
        var db = new TagDatabase();
        var tag = db.AddTag("arr", LogixDataTypes.DINT, elementCount: 8);

        Assert.Single(tag.Dims);
        Assert.Equal(8u, tag.Dims[0]);
        Assert.Equal(8, tag.ElementCount);
    }
}
