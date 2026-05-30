using System.Net;
using Xunit;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;
using EthernetIPSharp.Device;
using EthernetIPSharp.Safety;

namespace EthernetIPSharp.Safety.Tests;

public class SafetyConnectionTests
{
    [Fact]
    public void SafetyDevice_RegistersObjects()
    {
        var identity = new IdentityInfo { ProductName = "Safety Test" };
        var snn = new SafetyNetworkNumber([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        var device = new SafetyDevice(identity, IPAddress.Loopback, snn, 0xC0A80164);

        // Safety Supervisor (0x39) should be registered
        var supervisor = device.Dispatcher.GetClass(SafetySupervisorObject.ClassCode);
        Assert.NotNull(supervisor);
        Assert.Equal("Safety Supervisor", supervisor.Name);

        // Safety Validator (0x3A) should be registered
        var validator = device.Dispatcher.GetClass(SafetyValidatorObject.ClassCode);
        Assert.NotNull(validator);
        Assert.Equal("Safety Validator", validator.Name);

        // Safety handler should be set on connection manager
        Assert.NotNull(device.ConnectionManager.SafetyHandler);
    }

    [Fact]
    public void SafetyFrameCodec_EncodesAndDecodesBaseFormat()
    {
        byte pidS1 = SafetyCrc.PidCidSeedS1(1, 0x12345678, 1);
        ushort pidS3 = SafetyCrc.PidCidSeedS3(1, 0x12345678, 1);
        uint pidS5 = SafetyCrc.PidCidSeedS5(1, 0x12345678, 1);

        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var mode = ModeByte.Create(true, 0);
        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Base)];

        int written = SafetyFrameCodec.Encode(wire, data, SafetyFormat.Base, mode, 1000,
            pidS1, pidS3, pidS5);

        Assert.Equal(16, written); // Base Long 4-byte: 2*4 + 8

        var result = SafetyFrameCodec.Decode(wire.AsSpan(0, written), 4, SafetyFormat.Base,
            pidS1, pidS3, pidS5);

        Assert.True(result.CrcValid, result.ErrorMessage);
        Assert.Equal(data, result.ActualData);
        Assert.True(result.Mode.RunIdle);
    }

    [Fact]
    public void SafetyFrameCodec_DetectsCorruption()
    {
        byte pidS1 = SafetyCrc.PidCidSeedS1(1, 0x12345678, 1);
        ushort pidS3 = SafetyCrc.PidCidSeedS3(1, 0x12345678, 1);
        uint pidS5 = SafetyCrc.PidCidSeedS5(1, 0x12345678, 1);

        var data = new byte[] { 0x10, 0x20, 0x30 };
        var mode = ModeByte.Create(true, 0);
        var wire = new byte[SafetyFrameCodec.WireSize(data.Length, SafetyFormat.Base)];

        SafetyFrameCodec.Encode(wire, data, SafetyFormat.Base, mode, 1000,
            pidS1, pidS3, pidS5);

        // Valid decode
        var result = SafetyFrameCodec.Decode(wire, 3, SafetyFormat.Base, pidS1, pidS3, pidS5);
        Assert.True(result.CrcValid);
        Assert.Equal(data, result.ActualData);

        // Corrupt one byte
        wire[0] ^= 0x01;
        var corrupted = SafetyFrameCodec.Decode(wire, 3, SafetyFormat.Base, pidS1, pidS3, pidS5);
        Assert.False(corrupted.CrcValid);
    }

    [Fact]
    public void SafetyForwardOpenBuilder_ProducesValidData()
    {
        var snn = new SafetyNetworkNumber([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

        var config = new SafetyForwardOpenConfig
        {
            ConsumedAssembly = 100,
            ProducedAssembly = 101,
            ConfigAssembly = 10,
            ConsumedDataSize = 4,
            ProducedDataSize = 4,
            Rpi = 10000,
            Format = SafetyFormat.Base,
            Tunid = new UniqueNetworkId { Snn = snn, NodeAddress = 1 },
            Ounid = new UniqueNetworkId { Snn = snn, NodeAddress = 2 },
            Scid = new SafetyConfigurationId { Sccrc = 0x12345678, Scts = snn },
        };

        var (serviceData, cmPath) = SafetyForwardOpenBuilder.Build(config);

        Assert.Equal(new byte[] { 0x20, 0x06, 0x24, 0x01 }, cmPath);

        var fwdOpen = ForwardOpenRequest.Parse(serviceData);
        Assert.Equal(TransportClass.Class0, fwdOpen.TransportClass);

        var pathResult = ConnectionPathParser.Parse(fwdOpen.ConnectionPath.Span, fwdOpen);
        Assert.Equal(10u, pathResult.ConfigAssemblyInstance);
        Assert.Equal(100u, pathResult.ConsumedAssemblyInstance);
        Assert.Equal(101u, pathResult.ProducedAssemblyInstance);
        Assert.NotNull(pathResult.SafetySegment);
    }

    [Fact]
    public void IoConnection_IsSafety_SetBySafetySegment()
    {
        var conn = new IoConnection { IsSafety = true };
        Assert.True(conn.IsSafety);

        var standard = new IoConnection();
        Assert.False(standard.IsSafety);
    }

    [Fact]
    public void ConnectionPathParser_NoSafetySegment_ReturnsNull()
    {
        var path = new byte[] { 0x20, 0x04, 0x24, 0x0A, 0x2C, 0x64, 0x2C, 0x65 };
        var fwdOpen = new ForwardOpenRequest
        {
            OtoTParams = new NetworkConnectionParams { ConnectionType = 2 },
            TtoOParams = new NetworkConnectionParams { ConnectionType = 2 },
        };

        var result = ConnectionPathParser.Parse(path, fwdOpen);
        Assert.Null(result.SafetySegment);
    }
}
