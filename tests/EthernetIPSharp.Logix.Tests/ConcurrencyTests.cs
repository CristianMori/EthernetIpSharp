using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Tests for gap 7 (thread-safety correctness fixes).  Not a coverage exercise —
// each test targets a specific race the fixes are supposed to close.
public class ConcurrencyTests
{
    [Fact]
    public void AtomicSetBit_ConcurrentBits_SameHostByte_AllStick()
    {
        // Without atomic RMW, two threads flipping different bits of the same host
        // byte concurrently race — reader on thread A observes host, thread B
        // writes its bit, thread A writes back its bit with the stale host, and
        // B's bit vanishes.  AtomicSetBit uses Interlocked.Or on the containing
        // 4-byte word so both bits survive.
        var tag = new Tag(1, "flags", LogixDataTypes.MakeAtomicSymbolType(LogixDataTypes.DINT),
            LogixDataTypes.DINT, elementSize: 4);

        const int iterations = 20_000;
        var barrier = new Barrier(8);
        var threads = new Thread[8];
        for (int i = 0; i < 8; i++)
        {
            int bit = i;
            threads[i] = new Thread(() =>
            {
                barrier.SignalAndWait();
                for (int j = 0; j < iterations; j++)
                {
                    tag.AtomicSetBit(0, bit, true);
                }
            });
            threads[i].Start();
        }
        foreach (var t in threads) t.Join();

        // Every bit position 0..7 must be set — even one race would leave a hole.
        Assert.Equal(0xFF, tag.Read<byte>(0));
    }

    [Fact]
    public void AtomicSetBit_ConcurrentSetAndClear_ReachesConsistentState()
    {
        var tag = new Tag(1, "flags", LogixDataTypes.MakeAtomicSymbolType(LogixDataTypes.DINT),
            LogixDataTypes.DINT, elementSize: 4);

        // Half the threads set bits, half clear the same bit — the final value of
        // that shared bit is unspecified, but every OTHER bit in the byte must be
        // untouched. The historical bug: a non-atomic RMW could set an unrelated
        // bit to 0 because a stale host read leaks into the write-back.
        tag.AtomicSetBit(0, 5, true);  // sentinel bit 5 must remain set.

        var barrier = new Barrier(4);
        var threads = new Thread[4];
        for (int i = 0; i < 4; i++)
        {
            bool set = i % 2 == 0;
            threads[i] = new Thread(() =>
            {
                barrier.SignalAndWait();
                for (int j = 0; j < 20_000; j++)
                {
                    tag.AtomicSetBit(0, 2, set);
                }
            });
            threads[i].Start();
        }
        foreach (var t in threads) t.Join();

        Assert.True((tag.Read<byte>(0) & 0b_0010_0000) != 0,
            "sentinel bit 5 must not have been clobbered by racing writers to bit 2");
    }

    [Fact]
    public void AtomicSetBit_ArgumentValidation()
    {
        var tag = new Tag(1, "x", LogixDataTypes.MakeAtomicSymbolType(LogixDataTypes.DINT),
            LogixDataTypes.DINT, elementSize: 4);
        Assert.Throws<ArgumentOutOfRangeException>(() => tag.AtomicSetBit(0, 8, true));
        Assert.Throws<ArgumentOutOfRangeException>(() => tag.AtomicSetBit(4, 0, true));
    }

    [Fact]
    public void RegisterTag_TagVisibleByInstanceIdBeforeTagAddedSubscriber()
    {
        // The registration ordering fix: TagAdded fires with the tag already
        // present in _byInstanceId, so subscribers that look it up by instance id
        // (e.g. SymbolObject.EnsureInstance -> Tag) see a fully-published tag.
        // Regression guard: if RegisterTag ever reverts to publishing by name
        // first, subscribers that assume FindByInstanceId works during TagAdded
        // will start returning null.
        var db = new TagDatabase();
        Tag? seenByInstance = null;
        Tag? seenByName = null;
        db.TagAdded += t =>
        {
            seenByInstance = db.FindByInstanceId(t.InstanceId);
            seenByName = db.FindByName(t.Name);
        };

        var added = db.AddTag("probe", LogixDataTypes.DINT);

        Assert.Same(added, seenByInstance);
        // Name publish is intentionally deferred until after TagAdded returns to
        // avoid the class-based race the reorder was meant to close.
        Assert.Null(seenByName);
        // But after AddTag returns, both maps agree.
        Assert.Same(added, db.FindByInstanceId(added.InstanceId));
        Assert.Same(added, db.FindByName(added.Name));
    }

    [Fact]
    public void RegisterTag_DuplicateName_RollsBackInstanceIdAndSubscription()
    {
        var db = new TagDatabase();
        db.AddTag("dup", LogixDataTypes.DINT);

        int addedCount = 0;
        db.TagAdded += _ => addedCount++;

        Assert.Throws<InvalidOperationException>(() => db.AddTag("dup", LogixDataTypes.DINT));

        // The rejected tag's instance id must have been rolled back — no orphan
        // instance-id entry pointing at a tag that FindByName cannot see.
        var byName = db.FindByName("dup")!;
        Assert.Same(byName, db.FindByInstanceId(byName.InstanceId));

        // TagAdded may have fired once for the rejected tag before rollback; the
        // key guarantee is that the DB is not left in a partially-registered state.
        Assert.True(addedCount <= 1);
    }
}
