namespace EthernetIPSharp.Cip;

/// <summary>
/// CIP data type codes used in attribute definitions and tag type parameters.
/// Values match the CIP specification type IDs.
/// </summary>
public enum CipDataType : ushort
{
    /// <summary>Boolean — 1 byte.</summary>
    Bool = 0xC1,
    /// <summary>Signed 8-bit integer.</summary>
    Sint = 0xC2,
    /// <summary>Signed 16-bit integer.</summary>
    Int = 0xC3,
    /// <summary>Signed 32-bit integer.</summary>
    Dint = 0xC4,
    /// <summary>Signed 64-bit integer.</summary>
    Lint = 0xC5,
    /// <summary>Unsigned 8-bit integer.</summary>
    Usint = 0xC6,
    /// <summary>Unsigned 16-bit integer.</summary>
    Uint = 0xC7,
    /// <summary>Unsigned 32-bit integer.</summary>
    Udint = 0xC8,
    /// <summary>Unsigned 64-bit integer.</summary>
    Ulint = 0xC9,
    /// <summary>32-bit IEEE float.</summary>
    Real = 0xCA,
    /// <summary>64-bit IEEE double.</summary>
    Lreal = 0xCB,
    /// <summary>SHORT_STRING — 1 byte length + ASCII chars.</summary>
    ShortString = 0xDA,
    /// <summary>STRING — 2 byte length (UINT) + ASCII chars.</summary>
    String = 0xD0,
    /// <summary>8-bit bit string.</summary>
    Byte = 0xD1,
    /// <summary>16-bit bit string.</summary>
    Word = 0xD2,
    /// <summary>32-bit bit string.</summary>
    Dword = 0xD3,
    /// <summary>64-bit bit string.</summary>
    Lword = 0xD4,
}
