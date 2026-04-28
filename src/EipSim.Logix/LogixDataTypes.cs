namespace EipSim.Logix;

/// <summary>
/// Logix CIP tag type constants and utilities.
/// Tag type values match the Tag Type Service Parameter from 1756-PM020.
///
/// IMPORTANT: Logix STRING is NOT the CIP STRING type (0xD0).
/// Logix implements STRING as a predefined structure (UDT) with:
///   - LEN  (DINT, offset 0)  — current character count
///   - DATA (SINT[82], offset 4) — fixed-size ASCII character array
///   - Total: 88 bytes (4 + 82 + 2 padding)
///
/// The CIP STRING type (0xD0) uses a 2-byte UINT length prefix followed by
/// variable-length character data. Logix does NOT use this format for tag data.
/// When reading/writing a STRING tag, treat it as a structure, not as CIP STRING.
/// The structure handle comes from the Template Object — it is NOT a fixed value.
/// </summary>
public static class LogixDataTypes
{
    // --- Atomic tag type values (used in Read/Write Tag service parameter) ---

    /// <summary>BOOL — 1 byte. Bit position encoded in upper nibble (0x0nC1 where n=bit).</summary>
    public const ushort BOOL = 0x00C1;
    /// <summary>SINT — signed 8-bit integer, 1 byte.</summary>
    public const ushort SINT = 0x00C2;
    /// <summary>INT — signed 16-bit integer, 2 bytes.</summary>
    public const ushort INT = 0x00C3;
    /// <summary>DINT — signed 32-bit integer, 4 bytes.</summary>
    public const ushort DINT = 0x00C4;
    /// <summary>LINT — signed 64-bit integer, 8 bytes.</summary>
    public const ushort LINT = 0x00C5;
    /// <summary>REAL — 32-bit IEEE float, 4 bytes.</summary>
    public const ushort REAL = 0x00CA;
    /// <summary>LREAL — 64-bit IEEE double, 8 bytes.</summary>
    public const ushort LREAL = 0x00CB;
    /// <summary>DWORD — 32-bit bit string, 4 bytes.</summary>
    public const ushort DWORD = 0x00D3;

    // --- Logix STRING structure layout ---

    /// <summary>
    /// Logix STRING structure size in bytes (88 = 4 LEN + 82 DATA + 2 padding).
    /// Note: this is the predefined STRING type. User-created string types may differ.
    /// </summary>
    public const int StringStructureSize = 88;

    /// <summary>Byte offset of LEN (DINT) within a Logix STRING structure.</summary>
    public const int StringLenOffset = 0;

    /// <summary>Byte offset of DATA (SINT[82]) within a Logix STRING structure.</summary>
    public const int StringDataOffset = 4;

    /// <summary>Maximum character count for the predefined Logix STRING type.</summary>
    public const int StringMaxLength = 82;

    /// <summary>Returns the byte size of an atomic tag type, or -1 if unknown/structure.</summary>
    public static int GetElementSize(ushort tagType)
    {
        // Mask off BOOL bit position field (upper nibble of low byte)
        ushort baseType = (ushort)(tagType & 0x00FF);
        return baseType switch
        {
            0xC1 => 1,  // BOOL
            0xC2 => 1,  // SINT
            0xC3 => 2,  // INT
            0xC4 => 4,  // DINT
            0xC5 => 8,  // LINT
            0xCA => 4,  // REAL
            0xCB => 8,  // LREAL
            0xD3 => 4,  // DWORD
            _ => -1,
        };
    }

    /// <summary>
    /// Build the SymbolType attribute value for an atomic tag.
    /// Bits 14-13 encode array dimensions. Bit 15=0 for atomic.
    /// </summary>
    public static ushort MakeAtomicSymbolType(ushort tagType, int arrayDims = 0)
    {
        ushort symbolType = (ushort)(tagType & 0x00FF);
        symbolType |= (ushort)((arrayDims & 0x03) << 13);
        return symbolType;
    }

    /// <summary>
    /// Build the SymbolType attribute value for a structured tag.
    /// Bit 15=1. Bits 0-11 = template instance ID.
    /// </summary>
    public static ushort MakeStructSymbolType(ushort templateInstanceId, int arrayDims = 0)
    {
        ushort symbolType = (ushort)(0x8000 | (templateInstanceId & 0x0FFF));
        symbolType |= (ushort)((arrayDims & 0x03) << 13);
        return symbolType;
    }

    /// <summary>True if the symbol type indicates a structured tag (bit 15 set).</summary>
    public static bool IsStruct(ushort symbolType) => (symbolType & 0x8000) != 0;

    /// <summary>True if the symbol type indicates a system tag (bit 12 set).</summary>
    public static bool IsSystem(ushort symbolType) => (symbolType & 0x1000) != 0;

    /// <summary>Get the array dimensions from a symbol type (0-3).</summary>
    public static int GetArrayDims(ushort symbolType) => (symbolType >> 13) & 0x03;

    /// <summary>Get the template instance ID from a structured symbol type (bits 0-11).</summary>
    public static ushort GetTemplateId(ushort symbolType) => (ushort)(symbolType & 0x0FFF);

    /// <summary>
    /// Check if a template name matches the predefined Logix STRING type.
    /// The template name is "STRING" (may have suffix like ";nEAIA").
    /// </summary>
    public static bool IsLogixString(string templateName) =>
        templateName.StartsWith("STRING", StringComparison.OrdinalIgnoreCase) &&
        (templateName.Length == 6 || templateName[6] == ';');
}
