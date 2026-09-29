using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Tests for gap 9 (TagDatabase save/load).  Byte-compat with the C++/Rust/Python
// ports is guaranteed by the format documented on TagDatabasePersistence — those
// ports get matching test fixtures in later commits.
public class PersistenceTests
{
    [Fact]
    public void RoundTrip_PreservesEveryScalarAndArrayValue()
    {
        var db = MakeSchema();
        var rate = db.FindByName("rate")!;
        var arr = db.FindByName("arr")!;
        var flags = db.FindByName("flags")!;
        rate.Write<int>(0, 12345);
        for (int i = 0; i < 8; i++) arr.Write<int>(i * 4, 100 + i);
        flags.SetData(new byte[] { 0xAB, 0xCD, 0xEF, 0x12 });

        using var ms = new MemoryStream();
        TagDatabasePersistence.Save(db, ms);

        // Fresh database with same schema, then load.
        var db2 = MakeSchema();
        ms.Position = 0;
        var result = TagDatabasePersistence.Load(db2, ms);

        Assert.Equal(3, result.TagsRestored);
        Assert.Equal(0, result.TagsSkipped);
        Assert.Empty(result.Warnings);
        Assert.Equal(12345, db2.FindByName("rate")!.Read<int>(0));
        for (int i = 0; i < 8; i++)
            Assert.Equal(100 + i, db2.FindByName("arr")!.Read<int>(i * 4));
        Assert.Equal(0xAB, db2.FindByName("flags")!.Read<byte>(0));
        Assert.Equal(0xCD, db2.FindByName("flags")!.Read<byte>(1));
        Assert.Equal(0xEF, db2.FindByName("flags")!.Read<byte>(2));
        Assert.Equal(0x12, db2.FindByName("flags")!.Read<byte>(3));
    }

    [Fact]
    public void RoundTrip_ProgramScopedTags()
    {
        var db = new TagDatabase();
        db.AddTag("controllerTag", LogixDataTypes.DINT).Write<int>(0, 111);
        var prog = db.RegisterProgram("Cell");
        prog.AddTag("Rate", LogixDataTypes.DINT).Write<int>(0, 222);

        using var ms = new MemoryStream();
        TagDatabasePersistence.Save(db, ms);

        var db2 = new TagDatabase();
        db2.AddTag("controllerTag", LogixDataTypes.DINT);
        var prog2 = db2.RegisterProgram("Cell");
        prog2.AddTag("Rate", LogixDataTypes.DINT);

        ms.Position = 0;
        var result = TagDatabasePersistence.Load(db2, ms);

        Assert.Equal(2, result.TagsRestored);
        Assert.Equal(111, db2.FindByName("controllerTag")!.Read<int>(0));
        Assert.Equal(222, prog2.FindByName("Rate")!.Read<int>(0));
    }

    [Fact]
    public void Load_MissingTag_Skipped_WithWarning()
    {
        var db = new TagDatabase();
        db.AddTag("a", LogixDataTypes.DINT).Write<int>(0, 1);
        db.AddTag("b", LogixDataTypes.DINT).Write<int>(0, 2);

        using var ms = new MemoryStream();
        TagDatabasePersistence.Save(db, ms);

        // Load into a DB that only has "a" — "b" should skip with a warning,
        // and the stream must stay aligned.
        var db2 = new TagDatabase();
        db2.AddTag("a", LogixDataTypes.DINT);

        ms.Position = 0;
        var result = TagDatabasePersistence.Load(db2, ms);

        Assert.Equal(1, result.TagsRestored);
        Assert.Equal(1, result.TagsSkipped);
        Assert.Contains(result.Warnings, w => w.Contains("'b'"));
        Assert.Equal(1, db2.FindByName("a")!.Read<int>(0));
    }

    [Fact]
    public void Load_TypeMismatch_Skipped()
    {
        var db = new TagDatabase();
        db.AddTag("x", LogixDataTypes.DINT).Write<int>(0, 42);

        using var ms = new MemoryStream();
        TagDatabasePersistence.Save(db, ms);

        var db2 = new TagDatabase();
        db2.AddTag("x", LogixDataTypes.REAL); // Different type in the loading DB.

        ms.Position = 0;
        var result = TagDatabasePersistence.Load(db2, ms);

        Assert.Equal(0, result.TagsRestored);
        Assert.Equal(1, result.TagsSkipped);
        Assert.Contains(result.Warnings, w => w.Contains("tag_type mismatch"));
    }

    [Fact]
    public void Load_ExtraTagsInDb_LeftUntouched()
    {
        var db = new TagDatabase();
        db.AddTag("a", LogixDataTypes.DINT).Write<int>(0, 99);

        using var ms = new MemoryStream();
        TagDatabasePersistence.Save(db, ms);

        var db2 = new TagDatabase();
        db2.AddTag("a", LogixDataTypes.DINT);
        db2.AddTag("newlyAdded", LogixDataTypes.DINT).Write<int>(0, 555);

        ms.Position = 0;
        TagDatabasePersistence.Load(db2, ms);

        Assert.Equal(99, db2.FindByName("a")!.Read<int>(0));
        Assert.Equal(555, db2.FindByName("newlyAdded")!.Read<int>(0)); // untouched
    }

    [Fact]
    public void Load_UnknownProgram_SkipsWithoutStreamMisalignment()
    {
        var db = new TagDatabase();
        var prog = db.RegisterProgram("Gone");
        prog.AddTag("t", LogixDataTypes.DINT).Write<int>(0, 42);

        // Add a controller tag AFTER the program so we can prove the load walked
        // past the program section correctly (if it did not, the following
        // record would be misaligned and either throw or restore garbage).
        db.AddTag("kept", LogixDataTypes.DINT).Write<int>(0, 99);

        using var ms = new MemoryStream();
        TagDatabasePersistence.Save(db, ms);

        var db2 = new TagDatabase();
        db2.AddTag("kept", LogixDataTypes.DINT);
        // Program "Gone" not registered in db2.

        ms.Position = 0;
        var result = TagDatabasePersistence.Load(db2, ms);

        Assert.Equal(1, result.TagsRestored);
        Assert.Equal(1, result.TagsSkipped);
        Assert.Equal(99, db2.FindByName("kept")!.Read<int>(0));
    }

    [Fact]
    public void Load_BadMagic_Throws()
    {
        var db = new TagDatabase();
        using var ms = new MemoryStream(new byte[] { 0, 0, 0, 0, 1, 0, 0, 0 });
        Assert.Throws<InvalidDataException>(() => TagDatabasePersistence.Load(db, ms));
    }

    [Fact]
    public void Load_UnknownFutureVersion_Throws()
    {
        var db = new TagDatabase();
        // Magic OK, version = 99.
        using var ms = new MemoryStream(new byte[] {
            0x45, 0x49, 0x50, 0x53, 99, 0, 0, 0,
            0, 0, 0, 0, // 0 tags
            0, 0, 0, 0, // 0 programs
        });
        Assert.Throws<InvalidDataException>(() => TagDatabasePersistence.Load(db, ms));
    }

    [Fact]
    public void Load_DoesNotFireValueChanged()
    {
        // Restore uses SetDataSilent — subscribers must not observe restore as
        // if it were application writes, otherwise startup floods HMIs.
        var db = new TagDatabase();
        db.AddTag("x", LogixDataTypes.DINT).Write<int>(0, 42);
        using var ms = new MemoryStream();
        TagDatabasePersistence.Save(db, ms);

        var db2 = new TagDatabase();
        db2.AddTag("x", LogixDataTypes.DINT);
        int fired = 0;
        db2.AnyTagChanged += (_, _) => fired++;

        ms.Position = 0;
        TagDatabasePersistence.Load(db2, ms);
        Assert.Equal(0, fired);
    }

    private static TagDatabase MakeSchema()
    {
        var db = new TagDatabase();
        db.AddTag("rate", LogixDataTypes.DINT);
        db.AddTag("arr", LogixDataTypes.DINT, elementCount: 8);
        db.AddTag("flags", LogixDataTypes.BOOL, elementCount: 32);
        return db;
    }
}
