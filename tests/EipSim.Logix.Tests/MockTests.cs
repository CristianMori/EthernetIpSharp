using System.Buffers.Binary;
using EipSim.Cip;
using EipSim.Logix;
using NSubstitute;

namespace EipSim.Logix.Tests;

/// <summary>
/// Tests that exercise the Logix dispatcher with mocked dependencies.
/// No TCP sockets, no EipAdapter — pure in-process dispatch.
/// </summary>
public class MockTests
{
    [Fact]
    public void Dispatch_ReadTag_WithMockTagDatabase()
    {
        // Arrange: mock ITagDatabase that returns a pre-configured tag
        var mockDb = Substitute.For<ITagDatabase>();
        var tag = new Tag(1, "rate", LogixDataTypes.MakeAtomicSymbolType(LogixDataTypes.DINT),
                          LogixDataTypes.DINT, elementSize: 4, elementCount: 1);
        tag.Write(0, 42);

        mockDb.FindByName("rate").Returns(tag);
        mockDb.AllTags.Returns(new[] { tag });
        mockDb.AllTemplates.Returns(Enumerable.Empty<TemplateDefinition>());

        var dispatcher = new LogixDispatcher(mockDb);

        // Act: dispatch a Read Tag request with symbolic path "rate"
        var path = new CipPath { SymbolicName = "rate" };
        var requestData = new byte[] { 0x01, 0x00 }; // 1 element
        var response = dispatcher.Dispatch(TagServices.ReadTag, path, requestData);

        // Assert
        Assert.True(response.Status.IsSuccess);
        var data = response.Data.ToArray();
        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(data);
        Assert.Equal(LogixDataTypes.DINT, tagType);
        int value = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(2));
        Assert.Equal(42, value);

        // Verify the mock was called
        mockDb.Received(1).FindByName("rate");
    }

    [Fact]
    public void Dispatch_WriteTag_FiresValueChanged()
    {
        var mockDb = Substitute.For<ITagDatabase>();
        var tag = new Tag(1, "counter", LogixDataTypes.MakeAtomicSymbolType(LogixDataTypes.DINT),
                          LogixDataTypes.DINT, elementSize: 4);
        mockDb.FindByName("counter").Returns(tag);
        mockDb.AllTags.Returns(new[] { tag });
        mockDb.AllTemplates.Returns(Enumerable.Empty<TemplateDefinition>());

        var dispatcher = new LogixDispatcher(mockDb);

        // Subscribe to change event
        Tag? changedTag = null;
        TagChangeInfo changeInfo = default;
        tag.ValueChanged += (t, info) => { changedTag = t; changeInfo = info; };

        // Act: write 999 to "counter"
        var path = new CipPath { SymbolicName = "counter" };
        var writeData = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(writeData, LogixDataTypes.DINT);
        BinaryPrimitives.WriteUInt16LittleEndian(writeData.AsSpan(2), 1);
        BinaryPrimitives.WriteInt32LittleEndian(writeData.AsSpan(4), 999);

        var response = dispatcher.Dispatch(TagServices.WriteTag, path, writeData);

        // Assert
        Assert.True(response.Status.IsSuccess);
        Assert.Equal(999, tag.Read<int>());
        Assert.NotNull(changedTag);
        Assert.Equal("counter", changedTag!.Name);
        Assert.Equal(0, changeInfo.ByteOffset);
        Assert.Equal(4, changeInfo.ByteLength);
    }

    [Fact]
    public void Dispatch_ReadTag_UnknownTag_ReturnsPathError()
    {
        var mockDb = Substitute.For<ITagDatabase>();
        mockDb.FindByName("ghost").Returns((Tag?)null);
        mockDb.AllTags.Returns(Enumerable.Empty<Tag>());
        mockDb.AllTemplates.Returns(Enumerable.Empty<TemplateDefinition>());

        var dispatcher = new LogixDispatcher(mockDb);

        var path = new CipPath { SymbolicName = "ghost" };
        var response = dispatcher.Dispatch(TagServices.ReadTag, path, new byte[] { 0x01, 0x00 });

        Assert.Equal(0x05, response.Status.GeneralStatus); // Path destination unknown
    }

    [Fact]
    public void Dispatch_NoSymbolicName_NoClass_ReturnsPathError()
    {
        var mockDb = Substitute.For<ITagDatabase>();
        mockDb.AllTags.Returns(Enumerable.Empty<Tag>());
        mockDb.AllTemplates.Returns(Enumerable.Empty<TemplateDefinition>());

        var dispatcher = new LogixDispatcher(mockDb);

        // Path with no symbolic name and no class — falls through to base OnUnhandled
        var path = new CipPath { ClassId = 0xFF };
        var response = dispatcher.Dispatch(0x4C, path, new byte[] { 0x01, 0x00 });

        Assert.Equal(CipStatus.PathDestinationUnknown, response.Status.GeneralStatus);
    }

    [Fact]
    public void TagServices_ReadTag_InIsolation()
    {
        // Test tag service handler directly without any dispatcher
        var tag = new Tag(1, "test", 0x00C4, LogixDataTypes.DINT, elementSize: 4, elementCount: 3);
        tag.Write(0, 10);
        tag.Write(4, 20);
        tag.Write(8, 30);

        // Read 2 elements
        var requestData = new byte[] { 0x02, 0x00 };
        var response = TagServices.HandleReadTag(tag, 0x4C, requestData);

        Assert.True(response.Status.IsSuccess);
        var data = response.Data.ToArray();

        // tag_type (2) + 2 DINTs (8) = 10 bytes
        Assert.Equal(10, data.Length);
        Assert.Equal(LogixDataTypes.DINT, BinaryPrimitives.ReadUInt16LittleEndian(data));
        Assert.Equal(10, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(2)));
        Assert.Equal(20, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(6)));
    }

    [Fact]
    public void TagServices_WriteTag_TypeMismatch_InIsolation()
    {
        var tag = new Tag(1, "test", 0x00C4, LogixDataTypes.DINT, elementSize: 4);
        tag.Write(0, 123); // Set initial value

        var writeData = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(writeData, LogixDataTypes.REAL); // Wrong type
        BinaryPrimitives.WriteUInt16LittleEndian(writeData.AsSpan(2), 1);
        BinaryPrimitives.WriteInt32LittleEndian(writeData.AsSpan(4), 42);

        var response = TagServices.HandleWriteTag(tag, 0x4D, writeData);

        Assert.Equal(0xFF, response.Status.GeneralStatus);
        Assert.Contains((ushort)0x2107, response.Status.AdditionalStatus); // Type mismatch extended status
        Assert.Equal(123, tag.Read<int>()); // Value unchanged
    }

    [Fact]
    public void TagServices_ReadModifyWrite_InIsolation()
    {
        var tag = new Tag(1, "flags", 0x00C4, LogixDataTypes.DINT, elementSize: 4);
        tag.Write(0, 0b_0000_0101); // bits 0 and 2 set

        // Set bit 1, clear bit 2: OR=0x02, AND=0xFB
        var rmwData = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(rmwData, 1); // mask size = 1 byte
        rmwData[2] = 0x02; // OR mask: set bit 1
        rmwData[3] = 0xFB; // AND mask: clear bit 2

        var response = TagServices.HandleReadModifyWrite(tag, 0x4E, rmwData);

        Assert.True(response.Status.IsSuccess);
        Assert.Equal(0b_0000_0011, tag.Read<byte>()); // bits 0 and 1 set, bit 2 cleared
    }

    [Fact]
    public void CipPath_ParsesSymbolicSegment()
    {
        // "rate" = 91 04 72 61 74 65
        var pathBytes = new byte[] { 0x91, 0x04, 0x72, 0x61, 0x74, 0x65 };
        var (path, consumed) = CipPath.Parse(pathBytes);

        Assert.Equal("rate", path.SymbolicName);
        Assert.Null(path.ClassId);
        Assert.Equal(6, consumed);
    }

    [Fact]
    public void CipPath_ParsesDottedSymbolicSegments()
    {
        // "MyStruct" (91 08 ...) + "member" (91 06 ...)
        var seg1 = new byte[] { 0x91, 0x08, 0x4D, 0x79, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74 }; // "MyStruct" (8 chars, even)
        var seg2 = new byte[] { 0x91, 0x06, 0x6D, 0x65, 0x6D, 0x62, 0x65, 0x72 }; // "member" (6 chars, even)

        var pathBytes = new byte[seg1.Length + seg2.Length];
        seg1.CopyTo(pathBytes, 0);
        seg2.CopyTo(pathBytes, seg1.Length);

        var (path, _) = CipPath.Parse(pathBytes);

        Assert.Equal("MyStruct.member", path.SymbolicName);
    }

    [Fact]
    public void CipPath_ParsesSymbolicWithElementId()
    {
        // "counts" (91 06 ...) + element 5 (28 05)
        var pathBytes = new byte[]
        {
            0x91, 0x06, 0x63, 0x6F, 0x75, 0x6E, 0x74, 0x73, // "counts" (6 chars, even)
            0x28, 0x05, // Element ID 5 (8-bit logical)
        };

        var (path, _) = CipPath.Parse(pathBytes);

        Assert.Equal("counts", path.SymbolicName);
        Assert.Equal(5u, path.ElementId);
    }

    [Fact]
    public void CipPath_ParsesOddLengthSymbolicWithPadding()
    {
        // "abc" = 91 03 61 62 63 00 (3 chars + 1 pad byte)
        var pathBytes = new byte[] { 0x91, 0x03, 0x61, 0x62, 0x63, 0x00 };
        var (path, consumed) = CipPath.Parse(pathBytes);

        Assert.Equal("abc", path.SymbolicName);
        Assert.Equal(6, consumed); // 2 header + 3 chars + 1 pad
    }
}
