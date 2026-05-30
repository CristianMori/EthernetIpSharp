using System.Buffers.Binary;

namespace EthernetIPSharp.Cip;

/// <summary>
/// Encapsulation command codes sent over TCP port 44818.
/// </summary>
public enum EncapsulationCommand : ushort
{
    /// <summary>No operation. No reply generated. TCP only.</summary>
    Nop = 0x0000,
    /// <summary>Query available communication services. TCP or UDP.</summary>
    ListServices = 0x0004,
    /// <summary>Discover and identify targets. TCP or UDP.</summary>
    ListIdentity = 0x0063,
    /// <summary>Query non-CIP interfaces. TCP or UDP. Optional.</summary>
    ListInterfaces = 0x0064,
    /// <summary>Establish an encapsulation session. TCP only.</summary>
    RegisterSession = 0x0065,
    /// <summary>Terminate an encapsulation session. TCP only.</summary>
    UnregisterSession = 0x0066,
    /// <summary>Send unconnected explicit message (UCMM). TCP only.</summary>
    SendRRData = 0x006F,
    /// <summary>Send connected explicit message. TCP only.</summary>
    SendUnitData = 0x0070,
}

/// <summary>
/// Encapsulation status codes returned in the header.
/// </summary>
public enum EncapsulationStatus : uint
{
    /// <summary>Command completed successfully.</summary>
    Success = 0x0000,
    /// <summary>Unsupported or invalid encapsulation command.</summary>
    InvalidCommand = 0x0001,
    /// <summary>Insufficient memory to handle the command.</summary>
    InsufficientMemory = 0x0002,
    /// <summary>Poorly formed or incorrect data in the command.</summary>
    IncorrectData = 0x0003,
    /// <summary>Invalid session handle in the request.</summary>
    InvalidSessionHandle = 0x0064,
    /// <summary>Message of invalid length received.</summary>
    InvalidLength = 0x0065,
    /// <summary>Unsupported encapsulation protocol version.</summary>
    UnsupportedProtocolVersion = 0x0069,
}

/// <summary>
/// 24-byte EtherNet/IP encapsulation header.
/// All multi-byte fields are little-endian.
///
/// Wire layout:
///   Bytes 0-1:   Command
///   Bytes 2-3:   Length (payload size after this header)
///   Bytes 4-7:   Session Handle
///   Bytes 8-11:  Status
///   Bytes 12-19: Sender Context (opaque, echoed by target)
///   Bytes 20-23: Options (must be 0)
/// </summary>
public struct EncapsulationHeader
{
    /// <summary>Total size of the encapsulation header in bytes.</summary>
    public const int Size = 24;

    /// <summary>The encapsulation command.</summary>
    public EncapsulationCommand Command;

    /// <summary>Length in bytes of the data portion following this header.</summary>
    public ushort Length;

    /// <summary>Session handle assigned by the target during RegisterSession.</summary>
    public uint SessionHandle;

    /// <summary>Status of the encapsulation command.</summary>
    public EncapsulationStatus Status;

    /// <summary>8 bytes of opaque context chosen by the sender, echoed in the reply.</summary>
    public ulong SenderContext;

    /// <summary>Options flags. Must be 0 for all currently defined commands.</summary>
    public uint Options;

    /// <summary>
    /// Parse an encapsulation header from a 24-byte buffer.
    /// Throws ArgumentException if the buffer is too short.
    /// </summary>
    public static EncapsulationHeader Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < Size)
            throw new ArgumentException($"Encapsulation header requires {Size} bytes, got {data.Length}");

        return new EncapsulationHeader
        {
            Command = (EncapsulationCommand)BinaryPrimitives.ReadUInt16LittleEndian(data),
            Length = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2)),
            SessionHandle = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4)),
            Status = (EncapsulationStatus)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8)),
            SenderContext = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(12)),
            Options = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(20)),
        };
    }

    /// <summary>
    /// Write this header to a 24-byte buffer. Returns the number of bytes written (always 24).
    /// </summary>
    public readonly int WriteTo(Span<byte> data)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(data, (ushort)Command);
        BinaryPrimitives.WriteUInt16LittleEndian(data.Slice(2), Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(4), SessionHandle);
        BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(8), (uint)Status);
        BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(12), SenderContext);
        BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(20), Options);
        return Size;
    }
}
