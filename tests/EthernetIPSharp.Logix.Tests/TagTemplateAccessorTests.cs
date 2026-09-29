using EthernetIPSharp.Logix;

namespace EthernetIPSharp.Logix.Tests;

// Tests for gap 11a — Tag exposes its TemplateDefinition.
public class TagTemplateAccessorTests
{
    [Fact]
    public void StructTag_ExposesItsTemplate()
    {
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Timer",
            new TemplateMember("PRE", LogixDataTypes.DINT),
            new TemplateMember("ACC", LogixDataTypes.DINT));
        var tag = db.AddTag("t", tpl);

        Assert.NotNull(tag.Template);
        Assert.Same(tpl, tag.Template);
    }

    [Fact]
    public void AtomicTag_HasNullTemplate()
    {
        var db = new TagDatabase();
        var tag = db.AddTag("scalar", LogixDataTypes.DINT);
        Assert.Null(tag.Template);
    }

    [Fact]
    public void MultiDimStructTag_ExposesItsTemplate()
    {
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Row", new TemplateMember("X", LogixDataTypes.DINT));
        var tag = db.AddTag("grid", tpl, new uint[] { 4, 4 });
        Assert.Same(tpl, tag.Template);
    }

    [Fact]
    public void ProgramScopedStructTag_ExposesItsTemplate()
    {
        var db = new TagDatabase();
        var tpl = db.AddTemplate("Row", new TemplateMember("X", LogixDataTypes.DINT));
        var prog = db.RegisterProgram("MainProgram");
        var tag = prog.AddTag("t", tpl);
        Assert.Same(tpl, tag.Template);
    }
}
