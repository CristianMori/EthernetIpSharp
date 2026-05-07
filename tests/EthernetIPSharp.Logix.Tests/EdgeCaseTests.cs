using System.Buffers.Binary;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

/// <summary>
/// Tests for error paths and edge cases found via coverage analysis.
/// All pure dispatch tests — no TCP sockets needed.
/// </summary>
public class EdgeCaseTests
{
    private LogixDispatcher CreateDispatcher()
    {
        var logix = new LogixDispatcher();
        var rate = logix.Tags.AddTag("rate", LogixDataTypes.DINT);
        rate.Write(0, 100);
        logix.Tags.AddTag("bigarray", LogixDataTypes.SINT, elementCount: 2000);
        logix.Tags.AddTag("smallint", LogixDataTypes.INT);
        return logix;
    }

    // --- ReadTag error paths ---

    [Fact]
    public void ReadTag_EmptyRequest_ReturnsInsufficientData()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "rate" };
        var response = logix.Dispatch(0x4C, path, ReadOnlyMemory<byte>.Empty);
        Assert.Equal(0x13, response.Status.GeneralStatus);
    }

    [Fact]
    public void ReadTag_ElementCountBeyondEnd_ReturnsError()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "rate" };
        // rate is 1 DINT, ask for 100 elements
        var data = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(data, 100);
        var response = logix.Dispatch(0x4C, path, data);
        Assert.Equal(0xFF, response.Status.GeneralStatus);
        Assert.Contains((ushort)0x2105, response.Status.AdditionalStatus);
    }

    [Fact]
    public void ReadTag_MultipleElements_ReturnsAll()
    {
        var logix = CreateDispatcher();
        var arr = logix.Tags.FindByName("bigarray")!;
        arr.SetData(new byte[] { 10, 20, 30, 40, 50 });

        var path = new CipPath { SymbolicName = "bigarray" };
        var data = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(data, 5); // 5 SINTs
        var response = logix.Dispatch(0x4C, path, data);

        Assert.True(response.Status.IsSuccess);
        var resp = response.Data.ToArray();
        Assert.Equal(LogixDataTypes.SINT, BinaryPrimitives.ReadUInt16LittleEndian(resp));
        Assert.Equal(10, resp[2]);
        Assert.Equal(20, resp[3]);
        Assert.Equal(30, resp[4]);
        Assert.Equal(40, resp[5]);
        Assert.Equal(50, resp[6]);
    }

    // --- WriteTag error paths ---

    [Fact]
    public void WriteTag_EmptyRequest_ReturnsInsufficientData()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "rate" };
        var response = logix.Dispatch(0x4D, path, ReadOnlyMemory<byte>.Empty);
        Assert.Equal(0x13, response.Status.GeneralStatus);
    }

    [Fact]
    public void WriteTag_TooShortData_ReturnsInsufficientData()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "rate" };
        // tag_type + element_count = 4 bytes, but no actual data
        var data = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(data, LogixDataTypes.DINT);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), 1);
        var response = logix.Dispatch(0x4D, path, data);
        Assert.Equal(0x13, response.Status.GeneralStatus);
    }

    [Fact]
    public void WriteTag_ElementsBeyondEnd_ReturnsError()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "rate" };
        // Try to write 100 DINTs to a single-element tag
        var data = new byte[4 + 400];
        BinaryPrimitives.WriteUInt16LittleEndian(data, LogixDataTypes.DINT);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), 100);
        var response = logix.Dispatch(0x4D, path, data);
        Assert.Equal(0xFF, response.Status.GeneralStatus);
        Assert.Contains((ushort)0x2105, response.Status.AdditionalStatus);
    }

    // --- ReadTagFragmented error paths ---

    [Fact]
    public void ReadTagFragmented_EmptyRequest_ReturnsInsufficientData()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "bigarray" };
        var response = logix.Dispatch(0x52, path, ReadOnlyMemory<byte>.Empty);
        Assert.Equal(0x13, response.Status.GeneralStatus);
    }

    [Fact]
    public void ReadTagFragmented_OffsetBeyondEnd_ReturnsError()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "rate" };
        var data = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(data, 1); // 1 element
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(2), 99999); // way past end
        var response = logix.Dispatch(0x52, path, data);
        Assert.Equal(0xFF, response.Status.GeneralStatus);
    }

    [Fact]
    public void ReadTagFragmented_ReturnsStatus06WhenMoreData()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "bigarray" };
        var data = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(data, 2000); // all 2000 elements
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(2), 0); // start at 0
        var response = logix.Dispatch(0x52, path, data);
        Assert.Equal(0x06, response.Status.GeneralStatus); // more data
        Assert.True(response.Data.Length > 2); // has tag_type + partial data
    }

    // --- WriteTagFragmented error paths ---

    [Fact]
    public void WriteTagFragmented_EmptyRequest_ReturnsInsufficientData()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "bigarray" };
        var response = logix.Dispatch(0x53, path, ReadOnlyMemory<byte>.Empty);
        Assert.Equal(0x13, response.Status.GeneralStatus);
    }

    [Fact]
    public void WriteTagFragmented_TypeMismatch_ReturnsError()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "bigarray" }; // SINT array
        var data = new byte[10];
        BinaryPrimitives.WriteUInt16LittleEndian(data, LogixDataTypes.DINT); // wrong type
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 0);
        var response = logix.Dispatch(0x53, path, data);
        Assert.Equal(0xFF, response.Status.GeneralStatus);
        Assert.Contains((ushort)0x2107, response.Status.AdditionalStatus);
    }

    [Fact]
    public void WriteTagFragmented_WritesAtOffset()
    {
        var logix = CreateDispatcher();
        var arr = logix.Tags.FindByName("bigarray")!;

        var path = new CipPath { SymbolicName = "bigarray" };
        // Write 3 bytes at offset 10
        var data = new byte[8 + 3];
        BinaryPrimitives.WriteUInt16LittleEndian(data, LogixDataTypes.SINT);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), 2000); // total elements
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 10); // byte offset
        data[8] = 0xAA; data[9] = 0xBB; data[10] = 0xCC;

        var response = logix.Dispatch(0x53, path, data);
        Assert.True(response.Status.IsSuccess);

        Assert.Equal(0xAA, arr.Read<byte>(10));
        Assert.Equal(0xBB, arr.Read<byte>(11));
        Assert.Equal(0xCC, arr.Read<byte>(12));
    }

    // --- ReadModifyWrite error paths ---

    [Fact]
    public void ReadModifyWrite_InvalidMaskSize_ReturnsError()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "rate" };
        var data = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(data, 3); // invalid: must be 1,2,4,8,12
        var response = logix.Dispatch(0x4E, path, data);
        Assert.Equal(0x03, response.Status.GeneralStatus); // Bad parameter
    }

    [Fact]
    public void ReadModifyWrite_InsufficientMaskData_ReturnsError()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "rate" };
        // mask_size=4 needs 2+4+4=10 bytes, only provide 6
        var data = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(data, 4);
        var response = logix.Dispatch(0x4E, path, data);
        Assert.Equal(0x13, response.Status.GeneralStatus);
    }

    // --- Unsupported service code ---

    [Fact]
    public void UnsupportedService_ReturnsServiceNotSupported()
    {
        var logix = CreateDispatcher();
        var path = new CipPath { SymbolicName = "rate" };
        var response = logix.Dispatch(0xFF, path, new byte[] { 0x01, 0x00 });
        Assert.Equal(CipStatus.ServiceNotSupported, response.Status.GeneralStatus);
    }

    // --- Duplicate ForwardOpen ---

    [Fact]
    public void ForwardOpen_DuplicateTriad_ReturnsConnectionInUse()
    {
        var logix = CreateDispatcher();
        // We need a ConnectionManagerObject to test this
        var connMgr = new EthernetIPSharp.Connections.ConnectionManagerObject();
        connMgr.ValidateAssembly = _ => 16; // All assemblies valid with 16 bytes

        var cipClass = connMgr.CipClass;
        logix.RegisterClass(cipClass);

        // Build a Forward Open request
        var fwdOpenData = BuildForwardOpenData(connSerial: 42, origVendor: 1, origSerial: 0x1234);
        var path = new CipPath { ClassId = 0x06, InstanceId = 1 };
        var resp1 = logix.Dispatch(0x54, path, fwdOpenData);
        Assert.True(resp1.Status.IsSuccess, $"First ForwardOpen failed: 0x{resp1.Status.GeneralStatus:X2}");

        // Same triad again
        var resp2 = logix.Dispatch(0x54, path, fwdOpenData);
        Assert.Equal(0x01, resp2.Status.GeneralStatus); // Connection in use
        Assert.Contains((ushort)0x0100, resp2.Status.AdditionalStatus);
    }

    // --- ForwardClose with wrong triad ---

    [Fact]
    public void ForwardClose_WrongTriad_ReturnsConnectionNotFound()
    {
        var logix = CreateDispatcher();
        var connMgr = new EthernetIPSharp.Connections.ConnectionManagerObject();
        logix.RegisterClass(connMgr.CipClass);

        // Forward Close with a triad that was never opened
        var closeData = BuildForwardCloseData(connSerial: 999, origVendor: 1, origSerial: 0x1234);
        var path = new CipPath { ClassId = 0x06, InstanceId = 1 };
        var resp = logix.Dispatch(0x4E, path, closeData);
        Assert.Equal(0x01, resp.Status.GeneralStatus);
        Assert.Contains((ushort)0x0107, resp.Status.AdditionalStatus);
    }

    // --- Helpers ---

    private static byte[] BuildForwardOpenData(ushort connSerial, ushort origVendor, uint origSerial)
    {
        // Minimal Forward Open: enough fields to parse
        var connPath = new byte[] { 0x20, 0x04, 0x24, 0x01, 0x2C, 0x64, 0x2C, 0x65 };
        var data = new byte[36 + connPath.Length];
        int off = 0;
        data[off++] = 0x0A; // priority/time_tick
        data[off++] = 0xFA; // timeout_ticks
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(off), 0x11111111); off += 4; // OT conn ID
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(off), 0x00FEED00u | connSerial); off += 4; // TO conn ID
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(off), connSerial); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(off), origVendor); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(off), origSerial); off += 4;
        data[off++] = 0; off += 3; // timeout mult + reserved
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(off), 20000); off += 4; // OT RPI
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(off), 0x4010); off += 2; // OT params (P2P, 16 bytes)
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(off), 20000); off += 4; // TO RPI
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(off), 0x4010); off += 2; // TO params
        data[off++] = 0x01; // transport class 1
        data[off++] = (byte)(connPath.Length / 2);
        connPath.CopyTo(data.AsSpan(off));
        return data;
    }

    private static byte[] BuildForwardCloseData(ushort connSerial, ushort origVendor, uint origSerial)
    {
        var data = new byte[12];
        int off = 0;
        data[off++] = 0x0A; data[off++] = 0xFA;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(off), connSerial); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(off), origVendor); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(off), origSerial); off += 4;
        data[off++] = 0; data[off++] = 0;
        return data;
    }
}
