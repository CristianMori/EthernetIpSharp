using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Cip.Tests;

public class CipCrc16Tests
{
    [Fact]
    public void MatchesSpecTestVector1()
    {
        // From the CIP spec's abbreviated-structure encoding example:
        // formal encoding [A2][03][C7][C2][C3] (STRUCT { UINT, SINT, INT })
        // → CRC = 0x5159.
        var bytes = new byte[] { 0xA2, 0x03, 0xC7, 0xC2, 0xC3 };
        Assert.Equal(0x5159, CipCrc16.Calc(bytes));
    }

    [Fact]
    public void MatchesSpecTestVector2()
    {
        // Nested example from the same section:
        // formal encoding [A2][07][C7][A2][03][C7][C2][C3][C3]
        // → CRC = 0x26C7.
        var bytes = new byte[] { 0xA2, 0x07, 0xC7, 0xA2, 0x03, 0xC7, 0xC2, 0xC3, 0xC3 };
        Assert.Equal(0x26C7, CipCrc16.Calc(bytes));
    }

    [Fact]
    public void EmptyInput_ReturnsZero()
    {
        Assert.Equal(0, CipCrc16.Calc(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void SingleZeroByte_KeepsCrcZero()
    {
        // 0x00 XOR 0 → 0; eight shifts of 0 stay 0.
        Assert.Equal(0, CipCrc16.Calc(new byte[] { 0x00 }));
    }
}
