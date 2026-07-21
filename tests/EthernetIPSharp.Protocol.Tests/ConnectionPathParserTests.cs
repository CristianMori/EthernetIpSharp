using EthernetIPSharp.Connections;

namespace EthernetIPSharp.Protocol.Tests;

/// <summary>
/// Regression coverage for <see cref="ConnectionPathParser"/> — in
/// particular the Electronic Key `0x34` detection that was silently
/// dead code before the check-ordering fix.
/// </summary>
public class ConnectionPathParserTests
{
    private static ForwardOpenRequest WithP2P()
    {
        // Both directions non-null so the one-conn-point-both-directions
        // branch doesn't accidentally match for the safety-format test.
        return new ForwardOpenRequest
        {
            OtoTParams = NetworkConnectionParams.Parse(0x4001),  // P2P, size 1
            TtoOParams = NetworkConnectionParams.Parse(0x4001),
        };
    }

    [Fact]
    public void ElectronicKeyDetected_And_RestOfPathParsedCorrectly()
    {
        // Real ControlLogix Generic Ethernet Module Forward Open path:
        //   34 04                                Electronic Key, format 4
        //   00 00 00 00 00 00 00 00              8 key bytes (vendor/device/prod/rev = "any")
        //   20 04                                Class = Assembly
        //   24 69                                Instance = 105 (config)
        //   2C 66                                Conn point = 102 (O→T)
        //   2C 64                                Conn point = 100 (T→O)
        //   80 05  00×10                         Data segment (5 words config data)
        byte[] path =
        {
            0x34, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x04,
            0x24, 0x69,
            0x2C, 0x66,
            0x2C, 0x64,
            0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        var result = ConnectionPathParser.Parse(path, WithP2P());

        Assert.True(result.HasElectronicKey);
        Assert.Equal(105u, result.ConfigAssemblyInstance);
        Assert.Equal(102u, result.ConsumedAssemblyInstance);
        Assert.Equal(100u, result.ProducedAssemblyInstance);
        Assert.Equal(10, result.ConfigData.Length);
    }

    [Fact]
    public void ElectronicKeyOnly_ThenAssemblies_NoConfigData()
    {
        // Electronic key + standard shortcut, no config data segment.
        byte[] path =
        {
            0x34, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03,
        };

        var result = ConnectionPathParser.Parse(path, WithP2P());

        Assert.True(result.HasElectronicKey);
        Assert.Equal(1u, result.ConfigAssemblyInstance);
        Assert.Equal(2u, result.ConsumedAssemblyInstance);
        Assert.Equal(3u, result.ProducedAssemblyInstance);
        Assert.Equal(0, result.ConfigData.Length);
    }

    [Fact]
    public void NoElectronicKey_HasElectronicKeyFalse()
    {
        // Pure shortcut, no key segment.
        byte[] path = { 0x20, 0x04, 0x24, 0x05, 0x2C, 0x64, 0x2C, 0x66 };

        var result = ConnectionPathParser.Parse(path, WithP2P());

        Assert.False(result.HasElectronicKey);
        Assert.Equal(5u, result.ConfigAssemblyInstance);
        Assert.Equal(100u, result.ConsumedAssemblyInstance);
        Assert.Equal(102u, result.ProducedAssemblyInstance);
    }

    [Fact]
    public void UnknownKeyFormat_SkipsZeroBytes_SoRestStillParses()
    {
        // Format 0 (unknown) → skip 0 key bytes; the rest of the path
        // still needs to parse. Guards against a future regression that
        // "helpfully" consumes trailing bytes on an unknown key format.
        byte[] path =
        {
            0x34, 0x00,                       // key seg, unknown format
            0x20, 0x04, 0x24, 0x07, 0x2C, 0x08, 0x2C, 0x09,
        };

        var result = ConnectionPathParser.Parse(path, WithP2P());

        Assert.True(result.HasElectronicKey);
        Assert.Equal(7u, result.ConfigAssemblyInstance);
        Assert.Equal(8u, result.ConsumedAssemblyInstance);
        Assert.Equal(9u, result.ProducedAssemblyInstance);
    }
}
