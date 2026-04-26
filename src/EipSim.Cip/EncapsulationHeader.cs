using System.Buffers.Binary;

namespace EipSim.Cip;

public enum EncapsulationCommand : ushort
{
    Nop = 0x0000,
    ListServices = 0x0004,
    ListIdentity = 0x0063,
    ListInterfaces = 0x0064,
    RegisterSession = 0x0065,
    UnregisterSession = 0x0066,
    SendRRData = 0x006F,
    SendUnitData = 0x0070,
}

public enum EncapsulationStatus : uint
{
    Success = 0x0000,
    InvalidCommand = 0x0001,
    InsufficientMemory = 0x0002,
    IncorrectData = 0x0003,
    InvalidSessionHandle = 0x0064,
    InvalidLength = 0x0065,
    UnsupportedProtocolVersion = 0x0069,
}

/// <summary>
/// 24-byte EtherNet/IP encapsulation header (Vol2 §2-3.1).
/// All multi-byte fields are little-endian.
/// </summary>
public struct EncapsulationHeader
{
    public const int Size = 24;

    public EncapsulationCommand Command;
    public ushort Length;         // Length of data following header
    public uint SessionHandle;
    public uint Status;
    public ulong SenderContext;  // 8 bytes, opaque to target
    public uint Options;         // Must be 0

    public static EncapsulationHeader Parse(ReadOnlySpan<byte> data)
    {
        return new EncapsulationHeader
        {
            Command = (EncapsulationCommand)BinaryPrimitives.ReadUInt16LittleEndian(data),
            Length = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2)),
            SessionHandle = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4)),
            Status = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8)),
            SenderContext = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(12)),
            Options = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(20)),
        };
    }

    public readonly int WriteTo(Span<byte> data)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(data, (ushort)Command);
        BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(2), Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(4), SessionHandle);
        BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(8), Status);
        BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(12), SenderContext);
        BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(20), Options);
        return Size;
    }
}
