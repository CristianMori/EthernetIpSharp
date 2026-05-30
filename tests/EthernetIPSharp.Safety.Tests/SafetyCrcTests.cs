using System.Text;
using Xunit;
using EthernetIPSharp.Safety;

namespace EthernetIPSharp.Safety.Tests;

public class SafetyCrcTests
{
    // Reference check values: CRC of "123456789" (ASCII)
    private static readonly byte[] CheckInput = Encoding.ASCII.GetBytes("123456789");

    [Fact]
    public void CrcS1_CheckValue()
    {
        // CRC-S1 check = 0x4C with init=0xFF
        byte result = SafetyCrc.ComputeS1(CheckInput, 0xFF);
        Assert.Equal(0x4C, result);
    }

    [Fact]
    public void CrcS2_CheckValue()
    {
        // CRC-S2 check = 0xBF with init=0xFF
        byte result = SafetyCrc.ComputeS2(CheckInput, 0xFF);
        Assert.Equal(0xBF, result);
    }

    [Fact]
    public void CrcS3_CheckValue()
    {
        // CRC-S3 check = 0x9516 with init=0xFFFF
        ushort result = SafetyCrc.ComputeS3(CheckInput, 0xFFFF);
        Assert.Equal(0x9516, result);
    }

    [Fact]
    public void CrcS4_CheckValue()
    {
        // CRC-S4 check = 0x340BC6D9 with init=0xFFFFFFFF
        uint result = SafetyCrc.ComputeS4(CheckInput);
        Assert.Equal(0x340BC6D9u, result);
    }

    [Fact]
    public void CrcS1_EmptyInput()
    {
        byte result = SafetyCrc.ComputeS1([], 0x00);
        Assert.Equal(0x00, result);
    }

    [Fact]
    public void CrcS1_SingleByte()
    {
        byte result = SafetyCrc.ComputeS1([0x00], 0x00);
        Assert.Equal(0x00, result);

        byte result2 = SafetyCrc.ComputeS1([0x01], 0x00);
        Assert.Equal(0x37, result2);  // table[0 ^ 1] = table[1] = 0x37
    }

    [Fact]
    public void CrcS3_SingleByte_MatchesRef1()
    {
        // S3 over single byte 0xE0 with preset 0xFFFF
        ushort result = SafetyCrc.ComputeS3((byte)0xE0, 0xFFFF);
        ushort expected = SafetyCrc.ComputeS3(new byte[] { 0xE0 }, 0xFFFF);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void CrcS3_TwoBytes_MatchesRef2()
    {
        // S3 over UINT 0x1234 with preset 0xFFFF
        ushort result = SafetyCrc.ComputeS3((ushort)0x1234, 0xFFFF);
        // Manual: feed low byte 0x34, then high byte 0x12
        ushort expected = SafetyCrc.ComputeS3(new byte[] { 0x34, 0x12 }, 0xFFFF);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void CrcS1_Incremental()
    {
        // Feeding data in two parts should equal feeding all at once
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte all = SafetyCrc.ComputeS1(data, 0xFF);

        byte part1 = SafetyCrc.ComputeS1(data.AsSpan(0, 2), 0xFF);
        byte part2 = SafetyCrc.ComputeS1(data.AsSpan(2), part1);
        Assert.Equal(all, part2);
    }

    [Fact]
    public void CrcS3_Incremental()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        ushort all = SafetyCrc.ComputeS3(data, 0xFFFF);

        ushort part1 = SafetyCrc.ComputeS3(data.AsSpan(0, 2), 0xFFFF);
        ushort part2 = SafetyCrc.ComputeS3(data.AsSpan(2), part1);
        Assert.Equal(all, part2);
    }

    [Fact]
    public void PidCidSeed_S1_NonZero()
    {
        byte seed = SafetyCrc.PidCidSeedS1(0x0001, 0x12345678, 0x0001);
        Assert.NotEqual(0, seed);
    }

    [Fact]
    public void PidCidSeed_S3_NonZero()
    {
        ushort seed = SafetyCrc.PidCidSeedS3(0x0001, 0x12345678, 0x0001);
        Assert.NotEqual(0, seed);
    }

    [Fact]
    public void PidCidSeed_S5_NonZero()
    {
        uint seed = SafetyCrc.PidCidSeedS5(0x0001, 0x12345678, 0x0001);
        Assert.NotEqual(0u, seed);
    }

    [Fact]
    public void PidRolloverSeed_S3()
    {
        ushort pidSeed = SafetyCrc.PidCidSeedS3(0x0001, 0x12345678, 0x0001);
        ushort withRollover = SafetyCrc.PidRolloverSeedS3(1, pidSeed);
        // Rollover 0 should give different result than rollover 1
        ushort withRollover0 = SafetyCrc.PidRolloverSeedS3(0, pidSeed);
        Assert.NotEqual(withRollover, withRollover0);
    }

    [Fact]
    public void CrcS4_Standard_CRC32_Compatible()
    {
        // CRC-S4 is standard CRC-32 with init=0xFFFFFFFF and NO final XOR
        // (XorOut=0x00000000 — but it's reflected poly so the
        // result should match standard CRC-32 before final inversion)
        // The check value 0x340BC6D9 for "123456789" confirms this matches
        // the standard CRC-32 algorithm (which normally XORs with 0xFFFFFFFF
        // to get 0xCBF43926, but CIP Safety does NOT do the final XOR).
        uint result = SafetyCrc.ComputeS4(CheckInput);
        Assert.Equal(0x340BC6D9u, result);
    }
}
