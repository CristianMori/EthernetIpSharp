using Xunit;
using EthernetIPSharp.Safety;

namespace EthernetIPSharp.Safety.Tests;

public class SafetyNetworkSegmentTests
{
    [Fact]
    public void TargetFormat_RoundTrip()
    {
        var snn = new SafetyNetworkNumber([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

        var original = new SafetyNetworkSegment
        {
            Format = 0x00,
            Sccrc = 0xDEADBEEF,
            Scts = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            TimeCorrectionEpi = 0,
            TimeCorrectionParams = 0,
            Tunid = new UniqueNetworkId { Snn = snn, NodeAddress = 0xC0A80164 },
            Ounid = new UniqueNetworkId { Snn = snn, NodeAddress = 0xC0A80101 },
            PingIntervalMultiplier = 100,
            TimeCoordMsgMinMultiplier = 50,
            NetworkTimeExpectationMultiplier = 200,
            TimeoutMultiplier = 2,
            MaxConsumerNumber = 1,
            Cpcrc = 0x12345678,
            TimeCorrectionConnectionId = 0xFFFFFFFF,
        };

        var wire = new byte[56];
        int written = original.Encode(wire);
        Assert.Equal(56, written);
        Assert.Equal(0x50, wire[0]);
        Assert.Equal(0x1B, wire[1]); // 27 words

        var (parsed, consumed) = SafetyNetworkSegment.Parse(wire);
        Assert.Equal(56, consumed);
        Assert.Equal(original.Format, parsed.Format);
        Assert.Equal(original.Sccrc, parsed.Sccrc);
        Assert.Equal(original.Tunid.NodeAddress, parsed.Tunid.NodeAddress);
        Assert.Equal(original.Ounid.NodeAddress, parsed.Ounid.NodeAddress);
        Assert.Equal(original.PingIntervalMultiplier, parsed.PingIntervalMultiplier);
        Assert.Equal(original.TimeoutMultiplier, parsed.TimeoutMultiplier);
        Assert.Equal(original.MaxConsumerNumber, parsed.MaxConsumerNumber);
        Assert.Equal(original.Cpcrc, parsed.Cpcrc);
        Assert.Equal(original.TimeCorrectionConnectionId, parsed.TimeCorrectionConnectionId);
    }

    [Fact]
    public void ExtendedFormat_RoundTrip()
    {
        var snn = new SafetyNetworkNumber([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        var original = new SafetyNetworkSegment
        {
            Format = 0x02, // Extended
            Sccrc = 0x11223344,
            Scts = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            Tunid = new UniqueNetworkId { Snn = snn, NodeAddress = 1 },
            Ounid = new UniqueNetworkId { Snn = snn, NodeAddress = 2 },
            PingIntervalMultiplier = 10,
            TimeCoordMsgMinMultiplier = 5,
            NetworkTimeExpectationMultiplier = 20,
            TimeoutMultiplier = 3,
            MaxConsumerNumber = 1,
            MaxFaultNumber = 5,
            Cpcrc = 0xAABBCCDD,
            TimeCorrectionConnectionId = 0xFFFFFFFF,
            InitialTimeStamp = 1000,
            InitialRolloverValue = 42,
        };

        var wire = new byte[62]; // Extended format = 62 bytes
        int written = original.Encode(wire);
        Assert.Equal(62, written);
        Assert.Equal(0x1E, wire[1]); // 30 words

        var (parsed, consumed) = SafetyNetworkSegment.Parse(wire);
        Assert.Equal(62, consumed);
        Assert.Equal(0x02, parsed.Format);
        Assert.Equal(original.Sccrc, parsed.Sccrc);
        Assert.Equal(original.Cpcrc, parsed.Cpcrc);
        Assert.Equal(original.MaxFaultNumber, parsed.MaxFaultNumber);
        Assert.Equal(original.InitialTimeStamp, parsed.InitialTimeStamp);
        Assert.Equal(original.InitialRolloverValue, parsed.InitialRolloverValue);
        Assert.Equal(original.Tunid.NodeAddress, parsed.Tunid.NodeAddress);
    }

    [Fact]
    public void ConnectionPathParser_ExtractsSafetySegment()
    {
        // Build a connection path with assembly class + safety segment
        var path = new byte[8 + 56]; // assembly path + safety segment

        // Assembly: class 0x04, config instance 10, conn points 100, 101
        path[0] = 0x20; path[1] = 0x04;
        path[2] = 0x24; path[3] = 0x0A;
        path[4] = 0x2C; path[5] = 0x64;
        path[6] = 0x2C; path[7] = 0x65;

        // Safety segment at offset 8
        var segment = new SafetyNetworkSegment
        {
            Format = 0x00,
            Sccrc = 0x12345678,
            Scts = [0, 0, 0, 0, 0, 0],
            Tunid = new UniqueNetworkId { Snn = SafetyNetworkNumber.Zero, NodeAddress = 1 },
            Ounid = new UniqueNetworkId { Snn = SafetyNetworkNumber.Zero, NodeAddress = 2 },
            PingIntervalMultiplier = 100,
            TimeCoordMsgMinMultiplier = 50,
            NetworkTimeExpectationMultiplier = 200,
            TimeoutMultiplier = 2,
            MaxConsumerNumber = 1,
            Cpcrc = 0xAABBCCDD,
            TimeCorrectionConnectionId = 0xFFFFFFFF,
        };
        segment.Encode(path.AsSpan(8));

        var fwdOpen = new EthernetIPSharp.Connections.ForwardOpenRequest
        {
            OtoTParams = new EthernetIPSharp.Connections.NetworkConnectionParams
            {
                ConnectionType = 2,
                ConnectionSize = 100,
            },
            TtoOParams = new EthernetIPSharp.Connections.NetworkConnectionParams
            {
                ConnectionType = 2,
                ConnectionSize = 100,
            },
        };

        var result = EthernetIPSharp.Connections.ConnectionPathParser.Parse(path, fwdOpen);
        Assert.Equal(10u, result.ConfigAssemblyInstance);
        Assert.Equal(100u, result.ConsumedAssemblyInstance);
        Assert.Equal(101u, result.ProducedAssemblyInstance);
        Assert.NotNull(result.SafetySegment);
        Assert.Equal(56, result.SafetySegment.Value.Length);

        // Parse the extracted safety segment
        var (parsedSeg, _) = SafetyNetworkSegment.Parse(result.SafetySegment.Value.Span);
        Assert.Equal(0x12345678u, parsedSeg.Sccrc);
        Assert.Equal(0xAABBCCDDu, parsedSeg.Cpcrc);
    }
}
