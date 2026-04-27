using System.Collections.Concurrent;

namespace EipSim.Logix;

/// <summary>
/// In-memory tag database for the Logix simulator.
/// Stores tags indexed by name (case-insensitive) and by Symbol Object instance ID.
/// </summary>
public sealed class TagDatabase : ITagDatabase
{
    private readonly ConcurrentDictionary<string, Tag> _byName = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<uint, Tag> _byInstanceId = new();
    private uint _nextInstanceId = 1;

    /// <summary>Fires when any tag's data changes (from any source).</summary>
    public event Action<Tag, TagChangeInfo>? AnyTagChanged;

    /// <summary>Fires when a new tag is added.</summary>
    public event Action<Tag>? TagAdded;

    /// <summary>Fires when a new template is added.</summary>
    public event Action<TemplateDefinition>? TemplateAdded;

    /// <summary>Add an atomic tag.</summary>
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

        RegisterTag(tag);
        return tag;
    }

    /// <summary>Add a structured tag backed by a template.</summary>
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
            elementCount: elementCount);

        RegisterTag(tag);
        return tag;
    }

    private void RegisterTag(Tag tag)
    {
        if (!_byName.TryAdd(tag.Name, tag))
            throw new InvalidOperationException($"Tag '{tag.Name}' already exists");
        _byInstanceId[tag.InstanceId] = tag;

        tag.ValueChanged += OnTagValueChanged;
        TagAdded?.Invoke(tag);
    }

    private void OnTagValueChanged(Tag tag, TagChangeInfo info)
    {
        AnyTagChanged?.Invoke(tag, info);
    }

    /// <summary>Find a tag by name (case-insensitive). Supports dotted names for top-level lookup.</summary>
    public Tag? FindByName(string name)
    {
        // For dotted paths like "MyStruct.member", look up the root tag
        int dotIndex = name.IndexOf('.');
        string rootName = dotIndex >= 0 ? name[..dotIndex] : name;
        return _byName.TryGetValue(rootName, out var tag) ? tag : null;
    }

    /// <summary>Find a tag by its Symbol Object instance ID.</summary>
    public Tag? FindByInstanceId(uint instanceId) =>
        _byInstanceId.TryGetValue(instanceId, out var tag) ? tag : null;

    /// <summary>All tags in the database.</summary>
    public IEnumerable<Tag> AllTags => _byName.Values;

    /// <summary>Number of tags.</summary>
    public int Count => _byName.Count;

    // --- Template management ---

    private readonly ConcurrentDictionary<ushort, TemplateDefinition> _templates = new();
    private int _nextTemplateId = 0x100; // Start above atomic range

    /// <summary>Define a structure template (UDT).</summary>
    public TemplateDefinition AddTemplate(string name, params TemplateMember[] members)
    {
        ushort instanceId = (ushort)Interlocked.Increment(ref _nextTemplateId);

        // Calculate structure size and member offsets
        int offset = 0;
        var resolvedMembers = new TemplateMemberInfo[members.Length];
        for (int i = 0; i < members.Length; i++)
        {
            var m = members[i];
            int memberSize = m.ArraySize > 0
                ? LogixDataTypes.GetElementSize(m.DataType) * m.ArraySize
                : LogixDataTypes.GetElementSize(m.DataType);

            // Align to element boundary
            int elemSize = LogixDataTypes.GetElementSize(m.DataType);
            if (elemSize > 1)
                offset = (offset + elemSize - 1) / elemSize * elemSize;

            resolvedMembers[i] = new TemplateMemberInfo(m.Name, m.DataType, offset, m.ArraySize, elemSize);
            offset += memberSize;
        }

        // Pad to 32-bit boundary
        offset = (offset + 3) / 4 * 4;

        // Simple structure handle (in a real controller this is a CRC)
        ushort structHandle = (ushort)(0x8000 | instanceId);

        var template = new TemplateDefinition(
            instanceId: instanceId,
            name: name,
            structureHandle: structHandle,
            structureSize: (uint)offset,
            members: resolvedMembers);

        _templates[instanceId] = template;
        TemplateAdded?.Invoke(template);
        return template;
    }

    /// <summary>Find a template by its instance ID.</summary>
    public TemplateDefinition? FindTemplate(ushort instanceId) =>
        _templates.TryGetValue(instanceId, out var t) ? t : null;

    public IEnumerable<TemplateDefinition> AllTemplates => _templates.Values;
}

/// <summary>
/// Member definition for TagDatabase.AddTemplate().
/// Describes a member before offset calculation — just name, type, and optional array size.
/// </summary>
public readonly struct TemplateMember
{
    /// <summary>Member name.</summary>
    public string Name { get; }

    /// <summary>CIP data type code (e.g. LogixDataTypes.DINT).</summary>
    public ushort DataType { get; }

    /// <summary>Array size (0 for scalar members).</summary>
    public int ArraySize { get; }

    public TemplateMember(string name, ushort dataType, int arraySize = 0)
    {
        Name = name;
        DataType = dataType;
        ArraySize = arraySize;
    }
}

/// <summary>
/// Resolved template member with computed byte offset within the structure.
/// Produced by TagDatabase.AddTemplate() after alignment calculation.
/// </summary>
public readonly struct TemplateMemberInfo
{
    /// <summary>Member name.</summary>
    public string Name { get; }

    /// <summary>CIP data type code.</summary>
    public ushort DataType { get; }

    /// <summary>Byte offset of this member within the structure data.</summary>
    public int Offset { get; }

    /// <summary>Array size (0 for scalar members).</summary>
    public int ArraySize { get; }

    /// <summary>Size of one element in bytes.</summary>
    public int ElementSize { get; }

    public TemplateMemberInfo(string name, ushort dataType, int offset, int arraySize, int elementSize)
    {
        Name = name;
        DataType = dataType;
        Offset = offset;
        ArraySize = arraySize;
        ElementSize = elementSize;
    }
}

/// <summary>
/// A structure template definition corresponding to a CIP Template Object instance (class 0x6C).
/// Describes the layout and members of a user-defined data type (UDT).
/// </summary>
public sealed class TemplateDefinition
{
    /// <summary>Template Object instance ID.</summary>
    public ushort InstanceId { get; }

    /// <summary>Template/UDT name.</summary>
    public string Name { get; }

    /// <summary>Structure handle used as the tag type parameter in Read/Write Tag services.</summary>
    public ushort StructureHandle { get; }

    /// <summary>Total structure size in bytes when transmitted on the wire.</summary>
    public uint StructureSize { get; }

    /// <summary>Resolved member definitions with offsets.</summary>
    public IReadOnlyList<TemplateMemberInfo> Members { get; }

    /// <summary>Number of members in this structure.</summary>
    public int MemberCount => Members.Count;

    /// <summary>Template Object Definition Size in 32-bit words (used by Template Read service).</summary>
    public uint DefinitionSize { get; }

    public TemplateDefinition(ushort instanceId, string name, ushort structureHandle,
                              uint structureSize, TemplateMemberInfo[] members)
    {
        InstanceId = instanceId;
        Name = name;
        StructureHandle = structureHandle;
        StructureSize = structureSize;
        Members = members;

        // Definition size = (member_count * 8 bytes per member + name bytes + padding) / 4
        int nameBytes = name.Length + 1; // null-terminated
        foreach (var m in members) nameBytes += m.Name.Length + 1;
        int totalBytes = members.Length * 8 + nameBytes;
        totalBytes = (totalBytes + 3) / 4 * 4; // pad to 32-bit
        DefinitionSize = (uint)(totalBytes / 4) + 6; // +6 for header words (per spec: +23 bytes overhead)
    }
}
