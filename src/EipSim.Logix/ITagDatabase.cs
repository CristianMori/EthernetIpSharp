namespace EipSim.Logix;

/// <summary>
/// Tag storage and retrieval abstraction.
/// Implement to provide custom tag storage backends or mock for testing.
/// </summary>
public interface ITagDatabase
{
    Tag AddTag(string name, ushort tagType, int elementCount = 1);
    Tag AddTag(string name, TemplateDefinition template, int elementCount = 1);
    Tag? FindByName(string name);
    Tag? FindByInstanceId(uint instanceId);
    IEnumerable<Tag> AllTags { get; }
    int Count { get; }

    TemplateDefinition AddTemplate(string name, params TemplateMember[] members);
    TemplateDefinition? FindTemplate(ushort instanceId);
    IEnumerable<TemplateDefinition> AllTemplates { get; }

    event Action<Tag, TagChangeInfo>? AnyTagChanged;

    /// <summary>Fires when a new tag is added to the database.</summary>
    event Action<Tag>? TagAdded;

    /// <summary>Fires when a new template is added to the database.</summary>
    event Action<TemplateDefinition>? TemplateAdded;
}
