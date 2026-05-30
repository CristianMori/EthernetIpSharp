namespace EthernetIPSharp.Connections;

/// <summary>
/// Interface for handling safety-specific Forward Open validation and connection configuration.
/// Implemented by SafetyDevice and set on ConnectionManagerObject.SafetyHandler.
/// </summary>
public interface ISafetyConnectionHandler
{
    /// <summary>Target Vendor ID for safety application reply.</summary>
    ushort VendorId { get; }

    /// <summary>Target Device Serial Number for safety application reply.</summary>
    uint SerialNumber { get; }

    /// <summary>
    /// Validate a safety Forward Open before accepting.
    /// Returns null to accept, or an extended status code to reject.
    /// </summary>
    ushort? ValidateSafetyOpen(ReadOnlyMemory<byte> safetySegment, ForwardOpenRequest fwdOpen);

    /// <summary>
    /// Configure a safety connection after creation (compute CRC seeds, set SV instance, etc.).
    /// </summary>
    void ConfigureSafetyConnection(IoConnection conn, ForwardOpenRequest fwdOpen);
}
