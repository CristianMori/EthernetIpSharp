using System.Collections.Concurrent;

namespace EthernetIPSharp.Logix;

/// <summary>
/// A named tag scope belonging to a Logix program, with its own name and instance-id
/// space distinct from the controller scope.  Real 1756 controllers have controller
/// tags and program tags addressable as <c>Program:&lt;name&gt;.&lt;tag&gt;</c>; the same
/// tag name may appear in both scopes without collision.
///
/// Tags are added through this scope via <see cref="AddTag(string, ushort, int)"/> /
/// <see cref="AddTag(string, TemplateDefinition, int)"/>, resolved by
/// <see cref="LogixDispatcher"/> when the CIP request path starts with
/// <c>Program:&lt;name&gt;</c>, and enumerated at controller scope as a
/// <c>Program:&lt;name&gt;</c> pseudo-tag via Symbol Object Get_Instance_Attribute_List.
///
/// Instance IDs assigned here are local to the program: two programs may hold tags
/// with the same instance id.  Cross-program symbol-instance addressing is a
/// follow-up; the dispatcher currently addresses program tags by name only.
/// </summary>
public sealed class ProgramScope
{
    private readonly TagDatabase _parent;
    private readonly ConcurrentDictionary<string, Tag> _byName = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<uint, Tag> _byInstanceId = new();
    private uint _nextInstanceId;

    /// <summary>Program name (case-insensitive; e.g. "MainProgram", "Cell").</summary>
    public string Name { get; }

    /// <summary>
    /// Synthetic Symbol Object instance id used at controller scope for the
    /// <c>Program:&lt;name&gt;</c> pseudo-tag.  Fixed once assigned by the parent
    /// <see cref="TagDatabase"/>.
    /// </summary>
    public uint PseudoInstanceId { get; }

    internal ProgramScope(string name, uint pseudoInstanceId, TagDatabase parent)
    {
        Name = name;
        PseudoInstanceId = pseudoInstanceId;
        _parent = parent;
    }

    /// <summary>Add an atomic tag inside this program's scope.</summary>
    public Tag AddTag(string name, ushort tagType, int elementCount = 1)
    {
        int elementSize = LogixDataTypes.GetElementSize(tagType);
        if (elementSize < 0)
            throw new ArgumentException($"Unknown tag type 0x{tagType:X4}", nameof(tagType));
        int arrayDims = elementCount > 1 ? 1 : 0;
        ushort symbolType = LogixDataTypes.MakeAtomicSymbolType(tagType, arrayDims);
        var tag = new Tag(
            instanceId: Interlocked.Increment(ref _nextInstanceId),
            name: name,
            symbolType: symbolType,
            tagType: tagType,
            elementSize: elementSize,
            elementCount: elementCount);
        Register(tag);
        return tag;
    }

    /// <summary>Add a structured tag inside this program's scope.</summary>
    public Tag AddTag(string name, TemplateDefinition template, int elementCount = 1)
    {
        int arrayDims = elementCount > 1 ? 1 : 0;
        ushort symbolType = LogixDataTypes.MakeStructSymbolType(template.InstanceId, arrayDims);
        var tag = new Tag(
            instanceId: Interlocked.Increment(ref _nextInstanceId),
            name: name,
            symbolType: symbolType,
            tagType: template.StructureHandle,
            elementSize: (int)template.StructureSize,
            elementCount: elementCount)
        { Template = template };
        Register(tag);
        return tag;
    }

    private void Register(Tag tag)
    {
        if (!_byName.TryAdd(tag.Name, tag))
            throw new InvalidOperationException(
                $"Tag '{tag.Name}' already exists in program '{Name}'");
        _byInstanceId[tag.InstanceId] = tag;
    }

    /// <summary>Find a program-scoped tag by name (case-insensitive).</summary>
    public Tag? FindByName(string name) =>
        _byName.TryGetValue(name, out var t) ? t : null;

    /// <summary>Find a program-scoped tag by its program-local Symbol Object instance id.</summary>
    public Tag? FindByInstanceId(uint instanceId) =>
        _byInstanceId.TryGetValue(instanceId, out var t) ? t : null;

    /// <summary>All tags inside this program's scope.</summary>
    public IEnumerable<Tag> AllTags => _byName.Values;

    /// <summary>Number of tags inside this program.</summary>
    public int Count => _byName.Count;
}
