using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Tests for gap 8 (silent write path + optional dirty tracking).
public class SilentWriteTests
{
    [Fact]
    public void WriteSilent_DoesNotFireValueChanged()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("x", LogixDataTypes.DINT);

        int fired = 0;
        tag.ValueChanged += (_, _) => fired++;
        db.AnyTagChanged += (_, _) => fired++;

        for (int i = 0; i < 10_000; i++)
            tag.WriteSilent<int>(0, i);

        Assert.Equal(0, fired);
        Assert.Equal(9999, tag.Read<int>(0));
    }

    [Fact]
    public void Write_StillFiresValueChanged()
    {
        // Regression guard for gap 8: the noisy path must keep working. If the
        // silent path is accidentally introduced as the only path, subscribers
        // stop seeing updates and observers built on AnyTagChanged silently break.
        var db = new TagDatabase();
        var tag = db.AddTag("x", LogixDataTypes.DINT);

        int fired = 0;
        db.AnyTagChanged += (_, _) => fired++;

        tag.Write<int>(0, 42);
        Assert.Equal(1, fired);
    }

    [Fact]
    public void SetDataSilent_DoesNotFireValueChanged()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("x", LogixDataTypes.DINT);

        int fired = 0;
        db.AnyTagChanged += (_, _) => fired++;

        tag.SetDataSilent(new byte[] { 0xFF, 0xEE, 0xDD, 0xCC });

        Assert.Equal(0, fired);
        Assert.Equal(0xCCDDEEFFu, tag.Read<uint>(0));
    }

    [Fact]
    public void SuppressEvents_ShortCircuitsForwarder()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("x", LogixDataTypes.DINT);

        int fired = 0;
        db.AnyTagChanged += (_, _) => fired++;

        db.SuppressEvents = true;
        for (int i = 0; i < 1000; i++)
            tag.Write<int>(0, i);
        Assert.Equal(0, fired);

        db.SuppressEvents = false;
        tag.Write<int>(0, 99);
        Assert.Equal(1, fired);
    }

    [Fact]
    public void DirtyTracking_CollectsInstanceIds()
    {
        var db = new TagDatabase();
        var a = db.AddTag("a", LogixDataTypes.DINT);
        var b = db.AddTag("b", LogixDataTypes.DINT);
        var c = db.AddTag("c", LogixDataTypes.DINT);

        db.EnableDirtyTracking();

        a.Write<int>(0, 1);
        a.Write<int>(0, 2); // Same tag twice — should coalesce to one entry.
        b.Write<int>(0, 3);
        // c is untouched.

        var dirty = db.DrainDirty();
        Assert.Contains(a.InstanceId, dirty);
        Assert.Contains(b.InstanceId, dirty);
        Assert.DoesNotContain(c.InstanceId, dirty);
        Assert.Equal(2, dirty.Count);

        // Drain empties the set.
        Assert.Empty(db.DrainDirty());
    }

    [Fact]
    public void DirtyTracking_SkippedWhenSuppressed()
    {
        var db = new TagDatabase();
        var a = db.AddTag("a", LogixDataTypes.DINT);
        db.EnableDirtyTracking();
        db.SuppressEvents = true;

        a.Write<int>(0, 1);

        Assert.Empty(db.DrainDirty());
    }

    [Fact]
    public void DirtyTracking_OffByDefault()
    {
        var db = new TagDatabase();
        var a = db.AddTag("a", LogixDataTypes.DINT);
        a.Write<int>(0, 1);

        Assert.Empty(db.DrainDirty());
    }
}
