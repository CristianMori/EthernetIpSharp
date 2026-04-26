namespace EipSim.Logix;

/// <summary>
/// Logix CIP tag type constants and utilities.
/// Tag type values match the Tag Type Service Parameter from 1756-PM020.
/// </summary>
public static class LogixDataTypes
{
    // Atomic tag type values (used in Read/Write Tag service parameter)
    public const ushort BOOL = 0x00C1;
    public const ushort SINT = 0x00C2;
    public const ushort INT = 0x00C3;
    public const ushort DINT = 0x00C4;
    public const ushort LINT = 0x00C5;
    public const ushort REAL = 0x00CA;
    public const ushort DWORD = 0x00D3;

    /// <summary>Returns the byte size of an atomic tag type, or -1 if unknown.</summary>
    public static int GetElementSize(ushort tagType)
    {
        // Mask off BOOL bit position field (upper nibble of low byte)
        ushort baseType = (ushort)(tagType & 0x00FF);
        return baseType switch
        {
            0xC1 => 1,  // BOOL (stored as 1 byte)
            0xC2 => 1,  // SINT
            0xC3 => 2,  // INT
            0xC4 => 4,  // DINT
            0xC5 => 8,  // LINT
            0xCA => 4,  // REAL
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

    /// <summary>True if the symbol type indicates a structured tag.</summary>
    public static bool IsStruct(ushort symbolType) => (symbolType & 0x8000) != 0;

    /// <summary>True if the symbol type indicates a system tag (bit 12).</summary>
    public static bool IsSystem(ushort symbolType) => (symbolType & 0x1000) != 0;

    /// <summary>Get the array dimensions from a symbol type (0-3).</summary>
    public static int GetArrayDims(ushort symbolType) => (symbolType >> 13) & 0x03;

    /// <summary>Get the template instance ID from a structured symbol type.</summary>
    public static ushort GetTemplateId(ushort symbolType) => (ushort)(symbolType & 0x0FFF);
}
