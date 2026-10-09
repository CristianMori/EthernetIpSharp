using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Logix;

/// <summary>
/// Helpers for computing a Logix-style structure handle (the 16-bit value
/// returned as Template Object attribute 1 and used as the tag_type
/// parameter for struct Read/Write Tag services).
///
/// <para><b>Status: provisional.</b> The algorithm here follows CIP Vol 1
/// §C-6.1 / §C-6.2.1: hash the FormalStrucTypeSpec byte stream with the
/// CIP 16-bit CRC (polynomial 0xA001, init 0 — see <see cref="CipCrc16"/>).
/// The algorithm has <i>not</i> been validated against a captured Studio
/// 5000 Template_Read for a non-trivial UDT. Rockwell's Logix controllers
/// may use a variant of the FormalStrucTypeSpec encoding for UDTs that
/// contain nested structures, arrays, or BOOL members; wiring the output
/// here into <see cref="TagDatabase.AddTemplate"/> as the default handle
/// without that confirmation would ship a plausible-but-wrong value for
/// every struct tag the server exposes.</para>
///
/// <para>Scope today: only UDTs whose members are all scalar atomics
/// (no nested structs, no arrays, no scalar BOOLs that have been packed
/// into a hidden host byte). <see cref="TryComputeStructureHandle"/>
/// returns false and leaves the handle untouched for any other template.
/// Callers who want the computed handle for an atomic-only UDT can pass
/// the result in explicitly via
/// <see cref="TagDatabase.AddTemplate(TemplateDefinition)"/>.</para>
/// </summary>
public static class LogixStructureHandle
{
    // CIP Vol 1 §C-6.2.1 Table C-6.3 constants for the FormalStrucTypeSpec:
    //   [A2][length][type_code_1][type_code_2]...[type_code_N]
    // length is the number of type_code bytes that follow (so the structure
    // size on the wire is 2 + length). Each atomic type is a single byte.
    private const byte FormalStructPrefix = 0xA2;

    /// <summary>
    /// Build the FormalStrucTypeSpec byte stream for a UDT whose members
    /// are all scalar atomic types. Returns false when the template has
    /// any member the simple encoding cannot represent (nested struct,
    /// array, scalar BOOL packed into a hidden host, or an unknown atomic
    /// code); <paramref name="bytes"/> is empty on that path.
    /// </summary>
    public static bool TryBuildFormalStrucSpec(TemplateDefinition template, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (template is null) return false;

        var types = new List<byte>(template.Members.Count);
        foreach (var m in template.Members)
        {
            // Skip the hidden SINT host bytes AddTemplate inserts for packed
            // BOOLs — they are invisible to the formal encoding.
            if (m.Name.StartsWith("ZZZZZZZZZZ", StringComparison.Ordinal)) return false;
            if (m.ArraySize > 0) return false;                     // arrays — out of scope
            if ((m.DataType & 0x8000) != 0) return false;          // nested struct — out of scope
            if (LogixDataTypes.GetElementSize(m.DataType) <= 0) return false;
            byte code = (byte)(m.DataType & 0x00FF);
            // Scalar BOOLs that were packed share a host byte; the
            // ElementSize == 0 marker from AddTemplate tells us this is
            // the packed form, which the simple encoding cannot describe.
            if (code == 0xC1 && m.ElementSize == 0) return false;
            types.Add(code);
        }
        if (types.Count == 0) return false;
        if (types.Count > byte.MaxValue) return false;

        bytes = new byte[2 + types.Count];
        bytes[0] = FormalStructPrefix;
        bytes[1] = (byte)types.Count;
        for (int i = 0; i < types.Count; i++) bytes[2 + i] = types[i];
        return true;
    }

    /// <summary>
    /// Compute the structure handle for an atomic-only UDT by hashing its
    /// FormalStrucTypeSpec with <see cref="CipCrc16"/>. Returns false
    /// (handle left zero) when <see cref="TryBuildFormalStrucSpec"/> rejects
    /// the template.
    /// </summary>
    public static bool TryComputeStructureHandle(TemplateDefinition template, out ushort handle)
    {
        handle = 0;
        if (!TryBuildFormalStrucSpec(template, out var bytes)) return false;
        handle = CipCrc16.Calc(bytes);
        return true;
    }
}
