namespace EipSim.Logix;

/// <summary>
/// Tag storage and retrieval abstraction.
/// Implement to provide custom tag storage backends or mock for testing.
/// </summary>
public interface ITagDatabase
{
    /// <summary>Add an atomic tag with the given type and optional array size.</summary>
    Tag AddTag(string name, ushort tagType, int elementCount = 1);

    /// <summary>Add a structured tag backed by a template definition.</summary>
    Tag AddTag(string name, TemplateDefinition template, int elementCount = 1);

    /// <summary>Find a tag by name (case-insensitive). For dotted names, looks up the root tag.</summary>
    Tag? FindByName(string name);

    /// <summary>Find a tag by its Symbol Object instance ID.</summary>
    Tag? FindByInstanceId(uint instanceId);

    /// <summary>All tags in the database.</summary>
    IEnumerable<Tag> AllTags { get; }

    /// <summary>Number of tags.</summary>
    int Count { get; }

    /// <summary>Define a structure template (UDT) with the given members.</summary>
    TemplateDefinition AddTemplate(string name, params TemplateMember[] members);

    /// <summary>Find a template by its instance ID.</summary>
    TemplateDefinition? FindTemplate(ushort instanceId);

    /// <summary>All template definitions.</summary>
    IEnumerable<TemplateDefinition> AllTemplates { get; }

    /// <summary>Fires when any tag's data changes (from any source — CIP write or application code).</summary>
    event Action<Tag, TagChangeInfo>? AnyTagChanged;

    /// <summary>Fires when a new tag is added to the database.</summary>
    event Action<Tag>? TagAdded;

    /// <summary>Fires when a new template is added to the database.</summary>
    event Action<TemplateDefinition>? TemplateAdded;
}
