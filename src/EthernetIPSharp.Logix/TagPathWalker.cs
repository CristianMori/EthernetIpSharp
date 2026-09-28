using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Logix;

/// <summary>
/// Walks a sequence of <see cref="CipPathSegment"/> segments over a root <see cref="Tag"/> and
/// resolves the target byte offset, data type, element size, and (for BOOL members)
/// bit position inside the host byte.
///
/// The segments passed in are the ones AFTER the segment that selected the root tag —
/// i.e. member/element/index segments only, no scope prefix.
/// </summary>
public static class TagPathWalker
{
    /// <summary>Result of a successful walk.</summary>
    public readonly record struct WalkResult(
        int Offset,
        ushort TypeCode,
        int ElementSize,
        int? BitPos,
        TemplateDefinition? Template);

    /// <summary>
    /// Resolve the path against <paramref name="root"/>.  Returns <c>true</c> and
    /// populates <paramref name="result"/> on success; returns <c>false</c> and
    /// populates <paramref name="error"/> on a bad member name, wrong-kind segment,
    /// or index out of range.  Uses <paramref name="templates"/> to descend into
    /// nested struct members.
    /// </summary>
    public static bool TryWalk(
        Tag root,
        IReadOnlyList<CipPathSegment> segments,
        Func<ushort, TemplateDefinition?> templates,
        out WalkResult result,
        out string? error)
    {
        // Initial state points at the root tag itself.
        int offset = 0;
        ushort type = root.TagType;
        int elementSize = root.ElementSize;
        int? bitPos = null;
        TemplateDefinition? template = null;
        int pendingArraySize = 0; // >0 when we just landed on an array and haven't been indexed yet.

        // Resolve the initial template if the root is a struct.
        if (LogixDataTypes.IsStruct(root.SymbolType))
        {
            ushort tid = LogixDataTypes.GetTemplateId(root.SymbolType);
            template = templates(tid);
            if (template is null)
            {
                error = $"Root tag '{root.Name}' references unknown template 0x{tid:X4}";
                result = default;
                return false;
            }
        }

        // Root-level array dimension: if the tag has more than one element, the first
        // element segment indexes into the tag itself.
        if (root.ElementCount > 1)
            pendingArraySize = root.ElementCount;

        foreach (var seg in segments)
        {
            switch (seg)
            {
                case SymbolicPathSegment sym:
                    if (bitPos.HasValue)
                    {
                        error = $"Cannot drill into BOOL member with '{sym.Name}'";
                        result = default;
                        return false;
                    }
                    if (pendingArraySize > 0)
                    {
                        error = $"Cannot drill into array element without an index: '{sym.Name}'";
                        result = default;
                        return false;
                    }
                    if (template is null)
                    {
                        error = $"Cannot resolve member '{sym.Name}' on non-structure type 0x{type:X4}";
                        result = default;
                        return false;
                    }

                    if (!TryFindMember(template, sym.Name, out var member))
                    {
                        error = $"Member '{sym.Name}' not found in template '{template.Name}'";
                        result = default;
                        return false;
                    }

                    offset += member.Offset;
                    type = member.DataType;

                    if (type == LogixDataTypes.BOOL && member.ElementSize == 0)
                    {
                        // Scalar BOOL member inside a template: ArraySize stores the bit
                        // position (0-7). See TagDatabase.AddTemplate at line 150.
                        // BOOL arrays (member.ElementSize != 0) are handled by gap 6.
                        bitPos = member.ArraySize;
                        elementSize = 1;
                        template = null;
                        pendingArraySize = 0;
                    }
                    else if (LogixDataTypes.IsStruct(type))
                    {
                        ushort tid = LogixDataTypes.GetTemplateId(type);
                        template = templates(tid);
                        if (template is null)
                        {
                            error = $"Member '{sym.Name}' references unknown template 0x{tid:X4}";
                            result = default;
                            return false;
                        }
                        elementSize = (int)template.StructureSize;
                        pendingArraySize = member.ArraySize;
                    }
                    else
                    {
                        template = null;
                        elementSize = member.ElementSize > 0
                            ? member.ElementSize
                            : LogixDataTypes.GetElementSize(type);
                        pendingArraySize = member.ArraySize;
                    }
                    break;

                case ElementPathSegment el:
                    if (bitPos.HasValue)
                    {
                        error = "Cannot index into a BOOL member";
                        result = default;
                        return false;
                    }
                    if (pendingArraySize <= 0)
                    {
                        error = "Element index on non-array target";
                        result = default;
                        return false;
                    }
                    if (el.Index >= (uint)pendingArraySize)
                    {
                        error = $"Element index {el.Index} out of range (size {pendingArraySize})";
                        result = default;
                        return false;
                    }

                    offset += (int)el.Index * elementSize;
                    pendingArraySize = 0;
                    break;

                case LogicalPathSegment:
                    // Logical segments in a member path are not meaningful — dispatch handled
                    // class/instance/attribute before invoking the walker.
                    break;
            }
        }

        result = new WalkResult(offset, type, elementSize, bitPos, template);
        error = null;
        return true;
    }

    private static bool TryFindMember(TemplateDefinition template, string name, out TemplateMemberInfo member)
    {
        for (int i = 0; i < template.Members.Count; i++)
        {
            var m = template.Members[i];
            if (string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                member = m;
                return true;
            }
        }
        member = default;
        return false;
    }
}
