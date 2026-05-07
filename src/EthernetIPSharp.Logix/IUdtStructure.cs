namespace EthernetIPSharp.Logix;

/// <summary>
/// Interface for generated UDT structure classes.
/// Provides serialization to/from the raw byte blob that the PLC expects.
/// Implement this on code-generated classes produced by UdtCodeGenerator,
/// or manually for custom structure types.
/// </summary>
public interface IUdtStructure
{
    /// <summary>Structure handle used as the tag type parameter in Write Tag.</summary>
    ushort StructureHandle { get; }

    /// <summary>Total structure size in bytes on the wire.</summary>
    int StructureSize { get; }

    /// <summary>Marshal this structure to a byte blob matching the PLC wire format.</summary>
    byte[] ToBytes();

    /// <summary>Populate this structure from a byte blob read from the PLC.</summary>
    void FromBytes(byte[] data);
}
