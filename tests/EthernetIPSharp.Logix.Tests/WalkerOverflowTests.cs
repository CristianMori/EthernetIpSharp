using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

/// <summary>
/// Regression tests for the overflow in the walker-aware TagServices handlers.
/// Round-4 widened <c>HandleWriteTagFragmentedAt</c>, but
/// <c>HandleReadTagAt</c>, <c>HandleWriteTagAt</c>, and
/// <c>HandleReadTagFragmentedAt</c> still computed
/// <c>bytesToRead = elementCount * walked.ElementSize</c> as <c>int * int</c>,
/// which wraps negative on nested large UDTs and defeats the bound check.
/// </summary>
public class WalkerOverflowTests
{
    // walked.ElementSize = 100000 bytes (plausible for a nested UDT), paired
    // with elementCount near UINT16_MAX, products out at ~6.5 GB > int.MaxValue.
    private const int LargeElementSize = 100_000;

    private static TagPathWalker.WalkResult SyntheticWalked(int tagDataSize, int elementSize)
    {
        // Build a WalkResult pointing at offset 0 inside a hypothetical nested
        // atomic member whose ElementSize is `elementSize`. Template is null
        // (atomic member), so the 2-byte prefix path runs.
        return new TagPathWalker.WalkResult(
            Offset: 0,
            TypeCode: LogixDataTypes.DINT,
            ElementSize: elementSize,
            BitPos: null,
            Template: null);
    }

    private static Tag MakeTagWithDataSize(int dataSize)
    {
        // Allocate a tag with enough backing bytes that the walker's offset+size
        // bound check would still have to run — the overflow fix must reject the
        // request before that check, since the wrapped-negative product would
        // slip through.
        return new Tag(
            instanceId: 1,
            name: "big",
            symbolType: LogixDataTypes.SINT,
            tagType: LogixDataTypes.SINT,
            elementSize: 1,
            elementCount: dataSize);
    }

    [Fact]
    public void HandleReadTagAt_ElementCountTimesElementSizeOverflow_ReturnsTooMuchData()
    {
        var tag = MakeTagWithDataSize(1024);
        var walked = SyntheticWalked(tag.DataSize, LargeElementSize);

        var req = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(req, (ushort)65535);

        var resp = TagServices.HandleReadTagAt(tag, TagServices.ReadTag, req, walked);

        Assert.False(resp.Status.IsSuccess);
        Assert.Equal(CipStatus.TooMuchData, resp.Status.GeneralStatus);
    }

    [Fact]
    public void HandleWriteTagAt_ElementCountTimesElementSizeOverflow_ReturnsTooMuchData()
    {
        var tag = MakeTagWithDataSize(1024);
        var walked = SyntheticWalked(tag.DataSize, LargeElementSize);

        // Atomic-member write header: [tag_type:UINT][element_count:UINT]
        var req = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(req, LogixDataTypes.DINT);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), (ushort)65535);

        var resp = TagServices.HandleWriteTagAt(tag, TagServices.WriteTag, req, walked);

        Assert.False(resp.Status.IsSuccess);
        Assert.Equal(CipStatus.TooMuchData, resp.Status.GeneralStatus);
    }

    [Fact]
    public void HandleReadTagFragmentedAt_ElementCountTimesElementSizeOverflow_ReturnsTooMuchData()
    {
        var tag = MakeTagWithDataSize(1024);
        var walked = SyntheticWalked(tag.DataSize, LargeElementSize);

        var req = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(req, (ushort)65535);
        BinaryPrimitives.WriteUInt32LittleEndian(req.AsSpan(2), 0u);

        var resp = TagServices.HandleReadTagFragmentedAt(tag, TagServices.ReadTagFragmented, req, walked);

        Assert.False(resp.Status.IsSuccess);
        Assert.Equal(CipStatus.TooMuchData, resp.Status.GeneralStatus);
    }

    [Fact]
    public void HandleReadTagAt_SmallElementSize_StillSucceeds()
    {
        // Guard against overly-aggressive bound narrowing: elementCount*ElementSize
        // fits in int and inside DataSize must still succeed.
        var tag = MakeTagWithDataSize(64);
        var walked = SyntheticWalked(tag.DataSize, elementSize: 4);

        var req = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(req, 1); // single element

        var resp = TagServices.HandleReadTagAt(tag, TagServices.ReadTag, req, walked);

        Assert.True(resp.Status.IsSuccess);
    }
}
