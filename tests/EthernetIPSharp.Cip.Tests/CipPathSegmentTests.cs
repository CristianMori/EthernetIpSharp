using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Cip.Tests;

// Tests for the ordered Segments list on CipPath. Each shape mirrors what TagClient
// puts on the wire for the four addressing shapes the requirements doc names:
// program scope, member drilling, element + member, multi-dimensional element.
public class CipPathSegmentTests
{
    [Fact]
    public void ParsesProgramScopedTag()
    {
        // Program:MainProgram + MyTag => two symbolic segments in order.
        //   0x91 0x0C "MainProgram" (0-pad) + 0x91 0x05 "MyTag" (0-pad)
        var bytes = new byte[]
        {
            0x91, 12, (byte)'P', (byte)'r', (byte)'o', (byte)'g', (byte)'r', (byte)'a', (byte)'m', (byte)':', (byte)'M', (byte)'a', (byte)'i', (byte)'n',
            0x91,  5, (byte)'M', (byte)'y', (byte)'T', (byte)'a', (byte)'g', 0x00,
        };

        var (path, consumed) = CipPath.Parse(bytes);

        Assert.Equal(bytes.Length, consumed);
        Assert.Collection(path.Segments,
            s => Assert.Equal("Program:Main", Assert.IsType<SymbolicPathSegment>(s).Name),
            s => Assert.Equal("MyTag", Assert.IsType<SymbolicPathSegment>(s).Name));

        // Back-compat: flat SymbolicName still joins with '.'.
        Assert.Equal("Program:Main.MyTag", path.SymbolicName);
    }

    [Fact]
    public void ParsesMemberChain()
    {
        // Motor.Timer.PRE => three consecutive symbolic segments.
        //   0x91 0x05 "Motor" (0-pad) + 0x91 0x05 "Timer" (0-pad) + 0x91 0x03 "PRE" (0-pad)
        var bytes = new byte[]
        {
            0x91, 5, (byte)'M', (byte)'o', (byte)'t', (byte)'o', (byte)'r', 0x00,
            0x91, 5, (byte)'T', (byte)'i', (byte)'m', (byte)'e', (byte)'r', 0x00,
            0x91, 3, (byte)'P', (byte)'R', (byte)'E', 0x00,
        };

        var (path, consumed) = CipPath.Parse(bytes);

        Assert.Equal(bytes.Length, consumed);
        Assert.Collection(path.Segments,
            s => Assert.Equal("Motor", Assert.IsType<SymbolicPathSegment>(s).Name),
            s => Assert.Equal("Timer", Assert.IsType<SymbolicPathSegment>(s).Name),
            s => Assert.Equal("PRE", Assert.IsType<SymbolicPathSegment>(s).Name));
        Assert.Equal("Motor.Timer.PRE", path.SymbolicName);
    }

    [Fact]
    public void ParsesElementBetweenMembers()
    {
        // Line[2].Motor.Fault => symbolic + element(2) + symbolic + symbolic.
        //   0x91 0x04 "Line" + 0x28 0x02 + 0x91 0x05 "Motor" + 0x91 0x05 "Fault"
        var bytes = new byte[]
        {
            0x91, 4, (byte)'L', (byte)'i', (byte)'n', (byte)'e',
            0x28, 0x02,
            0x91, 5, (byte)'M', (byte)'o', (byte)'t', (byte)'o', (byte)'r', 0x00,
            0x91, 5, (byte)'F', (byte)'a', (byte)'u', (byte)'l', (byte)'t', 0x00,
        };

        var (path, consumed) = CipPath.Parse(bytes);

        Assert.Equal(bytes.Length, consumed);
        Assert.Collection(path.Segments,
            s => Assert.Equal("Line", Assert.IsType<SymbolicPathSegment>(s).Name),
            s => Assert.Equal(2u, Assert.IsType<ElementPathSegment>(s).Index),
            s => Assert.Equal("Motor", Assert.IsType<SymbolicPathSegment>(s).Name),
            s => Assert.Equal("Fault", Assert.IsType<SymbolicPathSegment>(s).Name));

        // Back-compat quirks (documented, not desired):
        //   flat SymbolicName still concatenates every 0x91 with '.',
        //   flat ElementId sees only 2 because there is only one element segment.
        Assert.Equal("Line.Motor.Fault", path.SymbolicName);
        Assert.Equal(2u, path.ElementId);
    }

    [Fact]
    public void ParsesMultiDimensionalIndices()
    {
        // Matrix[1,2] => symbolic + element(1) + element(2). Multiple element segments
        // now appear in the list (the old flat ElementId still last-write-wins).
        //   0x91 0x06 "Matrix" + 0x28 0x01 + 0x28 0x02
        var bytes = new byte[]
        {
            0x91, 6, (byte)'M', (byte)'a', (byte)'t', (byte)'r', (byte)'i', (byte)'x',
            0x28, 0x01,
            0x28, 0x02,
        };

        var (path, consumed) = CipPath.Parse(bytes);

        Assert.Equal(bytes.Length, consumed);
        Assert.Collection(path.Segments,
            s => Assert.Equal("Matrix", Assert.IsType<SymbolicPathSegment>(s).Name),
            s => Assert.Equal(1u, Assert.IsType<ElementPathSegment>(s).Index),
            s => Assert.Equal(2u, Assert.IsType<ElementPathSegment>(s).Index));

        // Back-compat: last element wins in the flat field.
        Assert.Equal(2u, path.ElementId);
    }

    [Fact]
    public void SegmentsListIsNeverNullOnObjectInitializer()
    {
        // Existing callers build CipPath via `new CipPath { SymbolicName = "..." }`
        // without touching Segments. The getter must return an empty list rather
        // than null so those callers don't NRE when new consumers iterate Segments.
        var path = new CipPath { SymbolicName = "rate" };

        Assert.NotNull(path.Segments);
        Assert.Empty(path.Segments);
    }

    [Fact]
    public void LogicalSegmentsAppearInOrder()
    {
        // Class 0x06 Instance 1 — the two logical segments both land in Segments,
        // in order, in addition to setting the flat ClassId/InstanceId fields.
        //   0x20 0x06 0x24 0x01
        var bytes = new byte[] { 0x20, 0x06, 0x24, 0x01 };

        var (path, _) = CipPath.Parse(bytes);

        Assert.Collection(path.Segments,
            s =>
            {
                var l = Assert.IsType<LogicalPathSegment>(s);
                Assert.Equal(LogicalSegmentKind.ClassId, l.Kind);
                Assert.Equal(6u, l.Value);
            },
            s =>
            {
                var l = Assert.IsType<LogicalPathSegment>(s);
                Assert.Equal(LogicalSegmentKind.InstanceId, l.Kind);
                Assert.Equal(1u, l.Value);
            });
        Assert.Equal(6u, path.ClassId);
        Assert.Equal(1u, path.InstanceId);
    }
}
