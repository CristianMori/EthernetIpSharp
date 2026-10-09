using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Cip.Tests;

public class UnconnectedSendBuilderTests
{
    [Fact]
    public void BuildInnerMr_EncodesServicePathAndData()
    {
        // Get_Attribute_Single (0x0E) on Identity(0x01)/instance 1/attr 7.
        var path = PathBuilder.BuildPath(0x01, 1, 7);
        var inner = UnconnectedSendBuilder.BuildInnerMr(0x0E, path, ReadOnlySpan<byte>.Empty);

        // Layout: service + path_size_words + path_bytes + (no service data).
        Assert.Equal(0x0E, inner[0]);
        Assert.Equal(path.Length / 2, inner[1]);
        Assert.Equal(path, inner.Skip(2).Take(path.Length).ToArray());
        Assert.Equal(2 + path.Length, inner.Length);
    }

    [Fact]
    public void Wrap_EmptyRoute_Throws()
    {
        var inner = new byte[] { 0x0E, 0x02, 0x20, 0x01, 0x24, 0x01 };
        Assert.Throws<ArgumentException>(() =>
            UnconnectedSendBuilder.Wrap(inner, Array.Empty<byte>()));
    }

    [Fact]
    public void Wrap_OddRouteLength_Throws()
    {
        var inner = new byte[] { 0x0E, 0x02, 0x20, 0x01, 0x24, 0x01 };
        Assert.Throws<ArgumentException>(() =>
            UnconnectedSendBuilder.Wrap(inner, new byte[] { 0x01 }));
    }

    [Fact]
    public void Wrap_MatchesReferenceWireLayout()
    {
        // Reference from CIP Vol 1 §3-5.5.4 example: an embedded 6-byte MR
        // (Get_Attribute_Single Identity[1].attr 7) with route "1,0" (2 bytes).
        //
        // Outer MR:
        //   0x52         ← Unconnected_Send service
        //   0x02         ← path_size = 2 words (4 bytes for CM path)
        //   0x20 0x06 0x24 0x01   ← Connection Manager path
        //   0x07 0xF9    ← priority_tick, timeout_ticks
        //   0x06 0x00    ← embedded_size = 6
        //   [6 bytes of embedded MR]
        //   (no pad — 6 is even)
        //   0x01 0x00    ← route_size_words=1 + reserved
        //   0x01 0x00    ← route path "1,0"
        var innerMr = new byte[] { 0x0E, 0x02, 0x20, 0x01, 0x24, 0x01 };
        var outerMr = UnconnectedSendBuilder.Wrap(innerMr, new byte[] { 0x01, 0x00 });

        var expected = new byte[]
        {
            0x52, 0x02, 0x20, 0x06, 0x24, 0x01,
            0x07, 0xF9,
            0x06, 0x00,
            0x0E, 0x02, 0x20, 0x01, 0x24, 0x01,
            0x01, 0x00,
            0x01, 0x00,
        };
        Assert.Equal(expected, outerMr);
    }

    [Fact]
    public void Wrap_OddSizedInnerMr_InsertsPadByte()
    {
        // Inner MR of odd length (7 bytes) forces one pad byte before the
        // route_path_size field.
        var innerMr = new byte[] { 0x0E, 0x02, 0x20, 0x01, 0x24, 0x01, 0xAA };
        var outerMr = UnconnectedSendBuilder.Wrap(innerMr, new byte[] { 0x01, 0x00 });

        // Locate the embedded_size field (at offset 8 of the outer MR — after
        // 2 service+psize + 4 CM path + 2 tick bytes) and count from there.
        // embedded_size = 7, then 7 embedded bytes, then 1 pad, then route_size=1, reserved=0, route=1,0.
        int embSizeOffset = 8;
        Assert.Equal(7, outerMr[embSizeOffset]);
        int routeSizeOffset = embSizeOffset + 2 + 7 + 1; // +size UINT + emb + pad
        Assert.Equal(1, outerMr[routeSizeOffset]);
        Assert.Equal(0, outerMr[routeSizeOffset + 1]); // reserved
    }
}
