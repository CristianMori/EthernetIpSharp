using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

/// <summary>
/// Regression tests for an asymmetry in Symbol Object instance handlers:
/// Read_Tag / Write_Tag honored <c>request.Path.ElementId</c>, but
/// Read_Tag_Fragmented (0x52) and Write_Tag_Fragmented (0x53) did not — a
/// client sending <c>Class 0x6B + Instance N + Element i + 0x52</c> read
/// from byte 0 of the tag instead of element i. The symbolic/walker path
/// was always correct; this covers the instance-ID-plus-element path that
/// <see cref="TagClient"/> uses after a <c>BrowseTagsAsync</c>.
///
/// Pulled from PR #1 exploration (@SRCthird).
/// </summary>
public class FragmentedElementOffsetTests
{
    private static byte[] FragmentedReadBody(ushort elementCount, uint byteOffsetInElements)
    {
        var buf = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(0), elementCount);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(2), byteOffsetInElements);
        return buf;
    }

    private static byte[] FragmentedWriteBody(ushort tagType, ushort elementCount, uint byteOffsetInElements, byte[] data)
    {
        var buf = new byte[8 + data.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(0), tagType);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(2), elementCount);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4), byteOffsetInElements);
        data.CopyTo(buf.AsSpan(8));
        return buf;
    }

    [Fact]
    public void SymbolObject_FragmentedRead_HonorsElementSegment()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("counts", LogixDataTypes.DINT, elementCount: 10);
        for (int i = 0; i < 10; i++) tag.Write(i * 4, 100 + i);

        var logix = new LogixDispatcher(db);
        // Class 0x6B · Instance <tag.InstanceId> · Element 5 · Read_Tag_Fragmented
        var path = new CipPath { ClassId = 0x6B, InstanceId = tag.InstanceId, ElementId = 5 };
        // Fragmented body: element_count=1, byte_offset=0
        var req = FragmentedReadBody(elementCount: 1, byteOffsetInElements: 0);

        var resp = logix.Dispatch(TagServices.ReadTagFragmented, path, req);

        Assert.True(resp.Status.IsSuccess, $"status=0x{resp.Status.GeneralStatus:X2}");
        // Reply payload: [type:UINT][data...]
        var replyData = resp.Data.Span;
        Assert.Equal(LogixDataTypes.DINT, BinaryPrimitives.ReadUInt16LittleEndian(replyData));
        Assert.Equal(105, BinaryPrimitives.ReadInt32LittleEndian(replyData.Slice(2)));
    }

    [Fact]
    public void SymbolObject_FragmentedRead_NoElementSegment_ReadsFromByteZero()
    {
        // Confirm the fix does not break the "no element segment" case.
        var db = new TagDatabase();
        var tag = db.AddTag("counts", LogixDataTypes.DINT, elementCount: 10);
        for (int i = 0; i < 10; i++) tag.Write(i * 4, 100 + i);

        var logix = new LogixDispatcher(db);
        var path = new CipPath { ClassId = 0x6B, InstanceId = tag.InstanceId };
        var req = FragmentedReadBody(elementCount: 1, byteOffsetInElements: 0);

        var resp = logix.Dispatch(TagServices.ReadTagFragmented, path, req);

        Assert.True(resp.Status.IsSuccess);
        Assert.Equal(100, BinaryPrimitives.ReadInt32LittleEndian(resp.Data.Span.Slice(2)));
    }

    [Fact]
    public void SymbolObject_FragmentedWrite_HonorsElementSegment()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("counts", LogixDataTypes.DINT, elementCount: 10);

        var logix = new LogixDispatcher(db);
        var path = new CipPath { ClassId = 0x6B, InstanceId = tag.InstanceId, ElementId = 7 };
        var payload = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(payload, 7777);
        var req = FragmentedWriteBody(LogixDataTypes.DINT, elementCount: 1,
                                       byteOffsetInElements: 0, payload);

        var resp = logix.Dispatch(TagServices.WriteTagFragmented, path, req);

        Assert.True(resp.Status.IsSuccess, $"status=0x{resp.Status.GeneralStatus:X2}");
        Assert.Equal(7777, tag.Read<int>(7 * 4));
        // Neighbors untouched.
        Assert.Equal(0, tag.Read<int>(6 * 4));
        Assert.Equal(0, tag.Read<int>(8 * 4));
    }

    [Fact]
    public void SymbolObject_FragmentedRead_AsymmetryParity_WithAtomicReadTag()
    {
        // Pin the fix by running the same element segment through both
        // atomic Read_Tag (which already honored elementId) and fragmented
        // Read_Tag_Fragmented. They must produce the same element value.
        var db = new TagDatabase();
        var tag = db.AddTag("counts", LogixDataTypes.DINT, elementCount: 10);
        for (int i = 0; i < 10; i++) tag.Write(i * 4, 1000 + i);

        var logix = new LogixDispatcher(db);
        var path = new CipPath { ClassId = 0x6B, InstanceId = tag.InstanceId, ElementId = 3 };

        var atomicReq = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(atomicReq, 1);
        var atomicResp = logix.Dispatch(TagServices.ReadTag, path, atomicReq);
        Assert.True(atomicResp.Status.IsSuccess);
        int atomicValue = BinaryPrimitives.ReadInt32LittleEndian(atomicResp.Data.Span.Slice(2));

        var fragReq = FragmentedReadBody(elementCount: 1, byteOffsetInElements: 0);
        var fragResp = logix.Dispatch(TagServices.ReadTagFragmented, path, fragReq);
        Assert.True(fragResp.Status.IsSuccess);
        int fragValue = BinaryPrimitives.ReadInt32LittleEndian(fragResp.Data.Span.Slice(2));

        Assert.Equal(1003, atomicValue);
        Assert.Equal(atomicValue, fragValue);
    }
}
