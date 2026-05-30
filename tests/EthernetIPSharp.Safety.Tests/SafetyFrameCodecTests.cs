using Xunit;
using EthernetIPSharp.Safety;

namespace EthernetIPSharp.Safety.Tests;

public class SafetyFrameCodecTests
{
    // Use a fixed PID for all tests
    private const ushort ConnSerial = 0x0001;
    private const ushort OrigVendor = 0x0001;
    private const uint OrigSerial = 0x12345678;

    private readonly byte _seedS1 = SafetyCrc.PidCidSeedS1(OrigVendor, OrigSerial, ConnSerial);
    private readonly ushort _seedS3 = SafetyCrc.PidCidSeedS3(OrigVendor, OrigSerial, ConnSerial);
    private readonly uint _seedS5 = SafetyCrc.PidCidSeedS5(OrigVendor, OrigSerial, ConnSerial);

    // --- Wire size tests ---

    [Theory]
    [InlineData(1, SafetyFormat.Base, 7)]    // 1 + 6 = 7
    [InlineData(2, SafetyFormat.Base, 8)]    // 2 + 6 = 8
    [InlineData(3, SafetyFormat.Base, 14)]   // 2*3 + 8 = 14
    [InlineData(10, SafetyFormat.Base, 28)]  // 2*10 + 8 = 28
    [InlineData(1, SafetyFormat.Extended, 7)]   // 1 + 6 = 7 (same overhead as Base!)
    [InlineData(2, SafetyFormat.Extended, 8)]   // 2 + 6 = 8
    [InlineData(3, SafetyFormat.Extended, 14)]  // 2*3 + 8 = 14 (same as Base Long)
    [InlineData(10, SafetyFormat.Extended, 28)] // 2*10 + 8 = 28
    public void WireSize_CorrectForAllFormats(int dataLen, SafetyFormat format, int expected)
    {
        Assert.Equal(expected, SafetyFrameCodec.WireSize(dataLen, format));
    }

    // --- Base Short round-trip ---

    [Fact]
    public void BaseShort_1Byte_RoundTrip()
    {
        var data = new byte[] { 0x42 };
        var mode = ModeByte.Create(true, 0);
        ushort timestamp = 1234;

        int wireLen = SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Base);
        var wire = new byte[wireLen];
        int written = SafetyFrameCodec.Encode(wire, data, SafetyFormat.Base, mode, timestamp,
            _seedS1, _seedS3, _seedS5);

        Assert.Equal(wireLen, written);

        var result = SafetyFrameCodec.Decode(wire, data.Length, SafetyFormat.Base,
            _seedS1, _seedS3, _seedS5);

        Assert.True(result.CrcValid, result.ErrorMessage);
        Assert.Equal(data, result.ActualData);
        Assert.Equal(timestamp, result.Timestamp);
        Assert.True(result.Mode.RunIdle);
    }

    [Fact]
    public void BaseShort_2Bytes_RoundTrip()
    {
        var data = new byte[] { 0xAA, 0x55 };
        var mode = ModeByte.Create(false, 2);
        ushort timestamp = 60000;

        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Base)];
        SafetyFrameCodec.Encode(wire, data, SafetyFormat.Base, mode, timestamp,
            _seedS1, _seedS3, _seedS5);

        var result = SafetyFrameCodec.Decode(wire, data.Length, SafetyFormat.Base,
            _seedS1, _seedS3, _seedS5);

        Assert.True(result.CrcValid);
        Assert.Equal(data, result.ActualData);
        Assert.False(result.Mode.RunIdle);
        Assert.Equal(2, result.Mode.PingCount);
    }

    // --- Base Long round-trip ---

    [Fact]
    public void BaseLong_4Bytes_RoundTrip()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var mode = ModeByte.Create(true, 1);
        ushort timestamp = 5000;

        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Base)];
        SafetyFrameCodec.Encode(wire, data, SafetyFormat.Base, mode, timestamp,
            _seedS1, _seedS3, _seedS5);

        var result = SafetyFrameCodec.Decode(wire, data.Length, SafetyFormat.Base,
            _seedS1, _seedS3, _seedS5);

        Assert.True(result.CrcValid, result.ErrorMessage);
        Assert.Equal(data, result.ActualData);
        Assert.Equal(timestamp, result.Timestamp);
    }

    [Fact]
    public void BaseLong_250Bytes_RoundTrip()
    {
        var data = new byte[250];
        for (int i = 0; i < 250; i++) data[i] = (byte)i;
        var mode = ModeByte.Create(true, 3);
        ushort timestamp = 0xFFFF;

        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Base)];
        SafetyFrameCodec.Encode(wire, data, SafetyFormat.Base, mode, timestamp,
            _seedS1, _seedS3, _seedS5);

        var result = SafetyFrameCodec.Decode(wire, data.Length, SafetyFormat.Base,
            _seedS1, _seedS3, _seedS5);

        Assert.True(result.CrcValid, result.ErrorMessage);
        Assert.Equal(data, result.ActualData);
    }

    // --- Extended Short round-trip ---

    [Fact]
    public void ExtendedShort_1Byte_RoundTrip()
    {
        var data = new byte[] { 0xFF };
        var mode = ModeByte.Create(true, 0);
        ushort timestamp = 100;

        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Extended)];
        SafetyFrameCodec.Encode(wire, data, SafetyFormat.Extended, mode, timestamp,
            _seedS1, _seedS3, _seedS5, rolloverCount: 5);

        var result = SafetyFrameCodec.Decode(wire, data.Length, SafetyFormat.Extended,
            _seedS1, _seedS3, _seedS5, rolloverCount: 5);

        Assert.True(result.CrcValid, result.ErrorMessage);
        Assert.Equal(data, result.ActualData);
    }

    // --- Extended Long round-trip ---

    [Fact]
    public void ExtendedLong_10Bytes_RoundTrip()
    {
        var data = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 };
        var mode = ModeByte.Create(true, 2);
        ushort timestamp = 30000;

        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Extended)];
        SafetyFrameCodec.Encode(wire, data, SafetyFormat.Extended, mode, timestamp,
            _seedS1, _seedS3, _seedS5, rolloverCount: 10);

        var result = SafetyFrameCodec.Decode(wire, data.Length, SafetyFormat.Extended,
            _seedS1, _seedS3, _seedS5, rolloverCount: 10);

        Assert.True(result.CrcValid, result.ErrorMessage);
        Assert.Equal(data, result.ActualData);
    }

    // --- Corruption detection ---

    [Fact]
    public void BaseLong_DetectsDataCorruption()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var mode = ModeByte.Create(true, 0);

        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Base)];
        SafetyFrameCodec.Encode(wire, data, SafetyFormat.Base, mode, 1000,
            _seedS1, _seedS3, _seedS5);

        // Corrupt one data byte
        wire[0] ^= 0x01;

        var result = SafetyFrameCodec.Decode(wire, data.Length, SafetyFormat.Base,
            _seedS1, _seedS3, _seedS5);

        Assert.False(result.CrcValid);
    }

    [Fact]
    public void BaseShort_DetectsTimestampCorruption()
    {
        var data = new byte[] { 0x42 };
        var mode = ModeByte.Create(true, 0);

        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Base)];
        SafetyFrameCodec.Encode(wire, data, SafetyFormat.Base, mode, 1000,
            _seedS1, _seedS3, _seedS5);

        // Corrupt timestamp byte
        wire[^2] ^= 0x01;

        var result = SafetyFrameCodec.Decode(wire, data.Length, SafetyFormat.Base,
            _seedS1, _seedS3, _seedS5);

        Assert.False(result.CrcValid);
    }

    [Fact]
    public void BaseLong_DetectsWrongPidSeed()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var mode = ModeByte.Create(true, 0);

        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Base)];
        SafetyFrameCodec.Encode(wire, data, SafetyFormat.Base, mode, 1000,
            _seedS1, _seedS3, _seedS5);

        // Decode with different seeds (wrong PID)
        byte wrongS1 = SafetyCrc.PidCidSeedS1(0x9999, 0x99999999, 0x9999);
        ushort wrongS3 = SafetyCrc.PidCidSeedS3(0x9999, 0x99999999, 0x9999);

        var result = SafetyFrameCodec.Decode(wire, data.Length, SafetyFormat.Base,
            wrongS1, wrongS3, 0);

        Assert.False(result.CrcValid);
    }

    // --- ModeByte tests ---

    [Fact]
    public void ModeByte_Create_SetsRedundantBits()
    {
        var mode = ModeByte.Create(true, 0);
        Assert.True(mode.RunIdle);
        Assert.True(mode.Validate());
        Assert.Equal(0, mode.PingCount);

        // run=1, ping=0 should produce 0x84 (matching real 1734 device)
        Assert.Equal(0x84, mode.Value);

        // N_Run_Idle (bit 4) should be 0 (complement of Run_Idle=1)
        Assert.Equal(0, mode.Value & 0x10);
        // N_TBD_Bit (bit 2) should be 1 (complement of TBD_Bit=0)
        Assert.NotEqual(0, mode.Value & 0x04);
    }

    [Fact]
    public void ModeByte_Create_MatchesRealDeviceValues()
    {
        // Verified against real 1734 PointIO captures
        Assert.Equal(0x14, ModeByte.Create(false, 0).Value); // cold start
        Assert.Equal(0x84, ModeByte.Create(true, 0).Value);
        Assert.Equal(0x85, ModeByte.Create(true, 1).Value);
        Assert.Equal(0x86, ModeByte.Create(true, 2).Value);
        Assert.Equal(0x87, ModeByte.Create(true, 3).Value);
    }

    [Fact]
    public void ModeByte_Validate_DetectsCorruption()
    {
        var mode = ModeByte.Create(true, 0);
        // Flip bit 4 (N_Run_Idle) to break complement relationship
        var corrupted = new ModeByte((byte)(mode.Value ^ 0x10));
        Assert.False(corrupted.Validate());
    }
}
