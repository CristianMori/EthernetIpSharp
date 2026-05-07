using System.Collections.Concurrent;

namespace EthernetIPSharp.Logix;

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

    /// <summary>
    /// Define a structure template (UDT) with proper Logix alignment and BOOL packing.
    ///
    /// Logix alignment rules (from 1756-PM020):
    /// - SINT/BOOL: 8-bit boundary (1 byte)
    /// - INT: 16-bit boundary (2 bytes)
    /// - DINT/REAL/DWORD: 32-bit boundary (4 bytes)
    /// - LINT/LREAL: 64-bit boundary (8 bytes)
    /// - Structures begin and end on 32-bit boundaries
    ///
    /// Logix BOOL packing:
    /// - Consecutive BOOLs in a UDT are packed into hidden SINT host members
    /// - Up to 8 BOOLs share one host SINT byte
    /// - Each BOOL records its bit position (0-7) in the Info field
    /// - The host SINT is named "ZZZZZZZZZZname#" and is not visible in Data Monitor
    /// </summary>
    public TemplateDefinition AddTemplate(string name, params TemplateMember[] members)
    {
        ushort instanceId = (ushort)Interlocked.Increment(ref _nextTemplateId);

        var resolvedMembers = new List<TemplateMemberInfo>();
        int offset = 0;
        int boolBitPos = 0;     // Current bit position within BOOL host byte
        int boolHostOffset = -1; // Offset of current BOOL host byte (-1 = no active host)
        int boolHostIndex = 0;   // Counter for naming host bytes

        for (int i = 0; i < members.Length; i++)
        {
            var m = members[i];

            if (m.DataType == LogixDataTypes.BOOL && m.ArraySize == 0)
            {
                // BOOL packing: pack into host SINT byte
                if (boolBitPos == 0 || boolBitPos >= 8)
                {
                    // Need a new host SINT byte — align to 1 byte (SINT alignment)
                    boolHostOffset = offset;
                    boolBitPos = 0;

                    // Add hidden host SINT member
                    string hostName = $"ZZZZZZZZZZ{name}{boolHostIndex++}";
                    resolvedMembers.Add(new TemplateMemberInfo(hostName, LogixDataTypes.SINT, boolHostOffset, 0, 1));
                    offset += 1;
                }

                // Add BOOL at current bit position within the host byte.
                // ArraySize field stores bit position for BOOLs (matches PLC template Info field).
                resolvedMembers.Add(new TemplateMemberInfo(m.Name, LogixDataTypes.BOOL, boolHostOffset, boolBitPos, 0));
                boolBitPos++;
            }
            else
            {
                // Non-BOOL: reset BOOL packing
                boolBitPos = 0;
                boolHostOffset = -1;

                int elemSize = LogixDataTypes.GetElementSize(m.DataType);
                if (elemSize <= 0) elemSize = 4; // Default for unknown/struct types

                // Alignment based on data type
                int alignment = GetAlignment(m.DataType, elemSize);
                offset = Align(offset, alignment);

                int memberSize = m.ArraySize > 0 ? elemSize * m.ArraySize : elemSize;

                resolvedMembers.Add(new TemplateMemberInfo(m.Name, m.DataType, offset, m.ArraySize, elemSize));
                offset += memberSize;
            }
        }

        // Structures end on 32-bit boundary
        offset = Align(offset, 4);

        // Simple structure handle (in a real controller this is a CRC)
        ushort structHandle = (ushort)(0x8000 | instanceId);

        var template = new TemplateDefinition(
            instanceId: instanceId,
            name: name,
            structureHandle: structHandle,
            structureSize: (uint)offset,
            members: resolvedMembers.ToArray());

        _templates[instanceId] = template;
        TemplateAdded?.Invoke(template);
        return template;
    }

    /// <summary>Find a template by its instance ID.</summary>
    public TemplateDefinition? FindTemplate(ushort instanceId) =>
        _templates.TryGetValue(instanceId, out var t) ? t : null;

    public IEnumerable<TemplateDefinition> AllTemplates => _templates.Values;

    /// <summary>
    /// Get the required alignment for a Logix data type.
    /// SINT/BOOL: 1, INT: 2, DINT/REAL/DWORD: 4, LINT/LREAL: 8.
    /// </summary>
    private static int GetAlignment(ushort dataType, int elementSize)
    {
        ushort baseType = (ushort)(dataType & 0x00FF);
        return baseType switch
        {
            0xC1 => 1,  // BOOL
            0xC2 => 1,  // SINT
            0xC3 => 2,  // INT
            0xC4 => 4,  // DINT
            0xC5 => 8,  // LINT — 8-byte aligned
            0xCA => 4,  // REAL
            0xCB => 8,  // LREAL — 8-byte aligned
            0xD3 => 4,  // DWORD
            _ => Math.Min(elementSize, 4), // Unknown: align to element size, max 4
        };
    }

    /// <summary>Align offset up to the given boundary.</summary>
    private static int Align(int offset, int alignment) =>
        (offset + alignment - 1) / alignment * alignment;
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
