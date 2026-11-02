using System.Buffers.Binary;
using System.Text;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

/// <summary>
/// Coverage for the CIP SHORT_STRING atomic type (0xDA) as a Logix tag type:
/// metadata, in-memory read/write helpers, and the CIP Read_Tag / Write_Tag
/// wire shape.  SHORT_STRING is independent of the Logix STRING UDT — the UDT
/// path (structure with LEN:DINT + DATA:SINT[82]) is covered in
/// <see cref="StructWirePrefixTests"/>.
///
/// Based on the exploration in PR #1 (SRCthird).  Narrowed to just the atomic
/// SHORT_STRING feature so it does not collide with the UDT STRING handling.
/// </summary>
public class ShortStringTests
{
    [Fact]
    public void Metadata_ShortStringElementIs81Bytes()
    {
        Assert.Equal(81, LogixDataTypes.GetElementSize(LogixDataTypes.SHORT_STRING));
        Assert.Equal(81, LogixDataTypes.ShortStringStorageSize);
        Assert.Equal(80, LogixDataTypes.ShortStringMaxLength);
    }

    [Fact]
    public void AddTag_ShortStringAtomic_HasExpectedLayout()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("name", LogixDataTypes.SHORT_STRING);

        Assert.True(tag.IsSString);
        Assert.Equal(81, tag.ElementSize);
        Assert.Equal(1, tag.ElementCount);
        Assert.Equal(81, tag.DataSize);
    }

    [Fact]
    public void AddTag_ShortStringArray_SizesInEighty_OneByteSlots()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("names", LogixDataTypes.SHORT_STRING, elementCount: 4);

        Assert.Equal(4, tag.ElementCount);
        Assert.Equal(81, tag.ElementSize);
        Assert.Equal(4 * 81, tag.DataSize);
    }

    // ---------- Helper round-trip ----------

    [Fact]
    public void WriteSString_ReadBackMatches()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("asset", LogixDataTypes.SHORT_STRING);

        tag.WriteSString("Asset-32");

        Assert.Equal("Asset-32", tag.ReadSString());
        Assert.Equal((byte)"Asset-32".Length, tag.GetData(0, 1)[0]);
    }

    [Fact]
    public void WriteSString_ArrayElement_IsolatesFromNeighbors()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("names", LogixDataTypes.SHORT_STRING, elementCount: 3);

        tag.WriteSString(0, "first");
        tag.WriteSString(1, "second-is-longer");
        tag.WriteSString(2, "third");

        Assert.Equal("first", tag.ReadSString(0));
        Assert.Equal("second-is-longer", tag.ReadSString(1));
        Assert.Equal("third", tag.ReadSString(2));
    }

    [Fact]
    public void WriteSString_ShorterOverLonger_ClearsTrailingBytes()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("asset", LogixDataTypes.SHORT_STRING);

        tag.WriteSString(new string('x', 40));
        tag.WriteSString("hi");

        Assert.Equal("hi", tag.ReadSString());
        // Confirm no leftover 'x' tails: scan from pos 3 to end should be zero.
        for (int i = 3; i < tag.DataSize; i++)
            Assert.Equal(0, tag.GetData(i, 1)[0]);
    }

    [Fact]
    public void WriteSString_RejectsOverMaxLength()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("asset", LogixDataTypes.SHORT_STRING);

        var ex = Assert.Throws<ArgumentException>(() =>
            tag.WriteSString(new string('x', LogixDataTypes.ShortStringMaxLength + 1)));
        Assert.Contains("SHORT_STRING", ex.Message);
    }

    [Fact]
    public void WriteSString_RejectsNonAscii()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("asset", LogixDataTypes.SHORT_STRING);

        Assert.Throws<ArgumentException>(() => tag.WriteSString("café"));
    }

    [Fact]
    public void ReadSString_OnNonShortStringTag_Throws()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("rate", LogixDataTypes.DINT);

        Assert.Throws<InvalidOperationException>(() => tag.ReadSString());
    }

    [Fact]
    public void WriteSString_OutOfRangeElement_Throws()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("names", LogixDataTypes.SHORT_STRING, elementCount: 2);

        Assert.Throws<ArgumentOutOfRangeException>(() => tag.WriteSString(5, "nope"));
    }

    // ---------- CIP wire shape ----------

    [Fact]
    public void HandleReadTag_ShortString_EmitsTwoByteAtomicPrefix()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("asset", LogixDataTypes.SHORT_STRING);
        tag.WriteSString("Asset-32");

        var resp = TagServices.HandleReadTag(tag, TagServices.ReadTag, new byte[] { 0x01, 0x00 });

        Assert.True(resp.Status.IsSuccess);
        var data = resp.Data.ToArray();

        // Atomic prefix is 2 bytes (CIP SHORT_STRING is NOT a structure, so no 0x02A0).
        Assert.Equal(2 + LogixDataTypes.ShortStringStorageSize, data.Length);
        ushort typeCode = BinaryPrimitives.ReadUInt16LittleEndian(data);
        Assert.Equal(LogixDataTypes.SHORT_STRING, typeCode);
        // Length byte then ASCII chars.
        Assert.Equal((byte)"Asset-32".Length, data[2]);
        Assert.Equal("Asset-32", Encoding.ASCII.GetString(data, 3, "Asset-32".Length));
    }

    [Fact]
    public void HandleWriteTag_ShortString_AcceptsAtomicHeader()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("asset", LogixDataTypes.SHORT_STRING);

        // Atomic Write_Tag header: [type:UINT][count:UINT][payload...]
        var payload = new byte[LogixDataTypes.ShortStringStorageSize];
        var value = "Asset-32";
        payload[0] = (byte)value.Length;
        Encoding.ASCII.GetBytes(value, 0, value.Length, payload, 1);

        var req = new byte[4 + payload.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(0), LogixDataTypes.SHORT_STRING);
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), 1);
        payload.CopyTo(req.AsSpan(4));

        var resp = TagServices.HandleWriteTag(tag, TagServices.WriteTag, req);

        Assert.True(resp.Status.IsSuccess);
        Assert.Equal("Asset-32", tag.ReadSString());
    }

    [Fact]
    public void HandleWriteTag_WrongTypeCode_Rejected()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("asset", LogixDataTypes.SHORT_STRING);

        var req = new byte[4 + LogixDataTypes.ShortStringStorageSize];
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(0), LogixDataTypes.DINT); // wrong
        BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(2), 1);

        var resp = TagServices.HandleWriteTag(tag, TagServices.WriteTag, req);

        Assert.False(resp.Status.IsSuccess);
        Assert.Equal(0xFF, resp.Status.GeneralStatus);
        Assert.Contains((ushort)0x2107, resp.Status.AdditionalStatus);
    }
}
