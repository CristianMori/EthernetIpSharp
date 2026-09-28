using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// End-to-end tests that drive LogixDispatcher via CipPath segment lists,
// verifying the walker path handles the four requirement-doc examples.
public class WalkerDispatcherTests
{
    private static (LogixDispatcher, Tag) MakeTimerTag()
    {
        var db = new TagDatabase();
        var timerTpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT),
            new TemplateMember("EN", LogixDataTypes.BOOL),
            new TemplateMember("TT", LogixDataTypes.BOOL),
            new TemplateMember("DN", LogixDataTypes.BOOL));
        var tag = db.AddTag("MyTimer", timerTpl);
        return (new LogixDispatcher(db), tag);
    }

    [Fact]
    public void ReadTag_MemberDrill_ReturnsMemberValue()
    {
        var (logix, tag) = MakeTimerTag();
        tag.Write<int>(0, 12345);  // PRE
        tag.Write<int>(4, 6789);   // ACC

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("MyTimer"),
                new SymbolicPathSegment("ACC"),
            },
        };
        var request = ElementCount(1);

        var resp = logix.Dispatch(TagServices.ReadTag, path, request);

        Assert.True(resp.Status.IsSuccess, $"status=0x{resp.Status.GeneralStatus:X2}");
        var span = resp.Data.Span;
        Assert.Equal(LogixDataTypes.DINT, BinaryPrimitives.ReadUInt16LittleEndian(span));
        Assert.Equal(6789, BinaryPrimitives.ReadInt32LittleEndian(span.Slice(2)));
    }

    [Fact]
    public void WriteTag_MemberDrill_UpdatesMemberOnly()
    {
        var (logix, tag) = MakeTimerTag();
        tag.Write<int>(0, 111);
        tag.Write<int>(4, 222);

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("MyTimer"),
                new SymbolicPathSegment("PRE"),
            },
        };
        var write = new byte[4 + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(write, LogixDataTypes.DINT);
        BinaryPrimitives.WriteUInt16LittleEndian(write.AsSpan(2), 1);
        BinaryPrimitives.WriteInt32LittleEndian(write.AsSpan(4), 999);

        var resp = logix.Dispatch(TagServices.WriteTag, path, write);

        Assert.True(resp.Status.IsSuccess, $"status=0x{resp.Status.GeneralStatus:X2}");
        Assert.Equal(999, tag.Read<int>(0));
        Assert.Equal(222, tag.Read<int>(4));  // ACC untouched.
    }

    [Fact]
    public void ReadTag_BoolMemberBit_ReturnsSingleBit()
    {
        var (logix, tag) = MakeTimerTag();
        // The three BOOLs pack into host byte at offset 8 (after PRE+ACC = 8).
        // EN=bit0, TT=bit1, DN=bit2 → set only DN.
        tag.Write<byte>(8, 0b_0000_0100);

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("MyTimer"),
                new SymbolicPathSegment("DN"),
            },
        };

        var resp = logix.Dispatch(TagServices.ReadTag, path, ElementCount(1));

        Assert.True(resp.Status.IsSuccess);
        var span = resp.Data.Span;
        Assert.Equal(LogixDataTypes.BOOL, BinaryPrimitives.ReadUInt16LittleEndian(span));
        Assert.Equal(1, span[2]);  // DN bit is set.
    }

    [Fact]
    public void ReadTag_BoolMemberBit_ReturnsZeroWhenClear()
    {
        var (logix, tag) = MakeTimerTag();
        tag.Write<byte>(8, 0b_0000_0100);  // only DN set

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("MyTimer"),
                new SymbolicPathSegment("EN"),
            },
        };

        var resp = logix.Dispatch(TagServices.ReadTag, path, ElementCount(1));

        Assert.True(resp.Status.IsSuccess);
        Assert.Equal(0, resp.Data.Span[2]);
    }

    [Fact]
    public void WriteTag_BoolMemberBit_SetsOnlyThatBit()
    {
        var (logix, tag) = MakeTimerTag();
        tag.Write<byte>(8, 0b_0000_0010);  // TT already set

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("MyTimer"),
                new SymbolicPathSegment("DN"),  // bit 2
            },
        };
        var write = new byte[5];
        BinaryPrimitives.WriteUInt16LittleEndian(write, LogixDataTypes.BOOL);
        BinaryPrimitives.WriteUInt16LittleEndian(write.AsSpan(2), 1);
        write[4] = 1;  // set

        var resp = logix.Dispatch(TagServices.WriteTag, path, write);

        Assert.True(resp.Status.IsSuccess);
        Assert.Equal(0b_0000_0110, tag.Read<byte>(8));  // TT still set, DN now set.
    }

    [Fact]
    public void WriteTag_BoolMemberBit_ClearsOnlyThatBit()
    {
        var (logix, tag) = MakeTimerTag();
        tag.Write<byte>(8, 0b_0000_0111);  // all three set

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("MyTimer"),
                new SymbolicPathSegment("TT"),  // bit 1
            },
        };
        var write = new byte[5];
        BinaryPrimitives.WriteUInt16LittleEndian(write, LogixDataTypes.BOOL);
        BinaryPrimitives.WriteUInt16LittleEndian(write.AsSpan(2), 1);
        write[4] = 0;  // clear

        var resp = logix.Dispatch(TagServices.WriteTag, path, write);

        Assert.True(resp.Status.IsSuccess);
        Assert.Equal(0b_0000_0101, tag.Read<byte>(8));
    }

    [Fact]
    public void ReadTag_ArrayElement_ReturnsElementValue()
    {
        var db = new TagDatabase();
        var arr = db.AddTag("arr", LogixDataTypes.DINT, elementCount: 5);
        for (int i = 0; i < 5; i++) arr.Write<int>(i * 4, 100 + i);
        var logix = new LogixDispatcher(db);

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("arr"),
                new ElementPathSegment(3),
            },
        };

        var resp = logix.Dispatch(TagServices.ReadTag, path, ElementCount(1));

        Assert.True(resp.Status.IsSuccess);
        Assert.Equal(103, BinaryPrimitives.ReadInt32LittleEndian(resp.Data.Span.Slice(2)));
    }

    [Fact]
    public void ReadTag_UnknownMember_ReturnsPathDestinationUnknown()
    {
        var (logix, _) = MakeTimerTag();

        var path = new CipPath
        {
            Segments = new CipPathSegment[]
            {
                new SymbolicPathSegment("MyTimer"),
                new SymbolicPathSegment("NoSuchThing"),
            },
        };

        var resp = logix.Dispatch(TagServices.ReadTag, path, ElementCount(1));

        Assert.Equal(0x05, resp.Status.GeneralStatus);
    }

    [Fact]
    public void FastPath_StillWorks_WhenSegmentsIsEmpty()
    {
        // Existing callers construct `new CipPath { SymbolicName = "..." }` without
        // populating Segments. The fast path must resolve them via FindByName as
        // before.
        var db = new TagDatabase();
        var rate = db.AddTag("rate", LogixDataTypes.DINT);
        rate.Write<int>(0, 42);
        var logix = new LogixDispatcher(db);

        var path = new CipPath { SymbolicName = "rate" };
        var resp = logix.Dispatch(TagServices.ReadTag, path, ElementCount(1));

        Assert.True(resp.Status.IsSuccess);
        Assert.Equal(42, BinaryPrimitives.ReadInt32LittleEndian(resp.Data.Span.Slice(2)));
    }

    private static byte[] ElementCount(ushort n)
    {
        var buf = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buf, n);
        return buf;
    }
}
