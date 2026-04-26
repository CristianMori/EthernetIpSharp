namespace EipSim.Cip;

public enum CipDataType : ushort
{
    Bool = 0xC1,
    Sint = 0xC2,     // int8
    Int = 0xC3,      // int16
    Dint = 0xC4,     // int32
    Lint = 0xC5,     // int64
    Usint = 0xC6,    // uint8
    Uint = 0xC7,     // uint16
    Udint = 0xC8,    // uint32
    Ulint = 0xC9,    // uint64
    Real = 0xCA,     // float32
    Lreal = 0xCB,    // float64
    ShortString = 0xDA,
    String = 0xD0,
    Byte = 0xD1,
    Word = 0xD2,
    Dword = 0xD3,
    Lword = 0xD4,
}
