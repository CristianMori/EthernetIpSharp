namespace EthernetIPSharp.Cip;

/// <summary>
/// Device identity information used in ListIdentity responses and the Identity CIP object (class 0x01).
/// All fields map to Identity Object instance 1 attributes per Vol1 Chapter 5.
/// </summary>
public sealed class IdentityInfo
{
    /// <summary>CIP class code for Identity Object.</summary>
    public const uint ClassCode = 0x01;

    /// <summary>Manufacturer's vendor ID (attribute 1).</summary>
    public ushort VendorId { get; init; }

    /// <summary>Device type code (attribute 2).</summary>
    public ushort DeviceType { get; init; }

    /// <summary>Product code assigned by the vendor (attribute 3).</summary>
    public ushort ProductCode { get; init; }

    /// <summary>Major revision number (attribute 4, byte 0).</summary>
    public byte MajorRevision { get; init; }

    /// <summary>Minor revision number (attribute 4, byte 1).</summary>
    public byte MinorRevision { get; init; }

    /// <summary>Device serial number (attribute 6).</summary>
    public uint SerialNumber { get; init; }

    /// <summary>Human-readable product name (attribute 7, SHORT_STRING).</summary>
    public string ProductName { get; init; } = "EthernetIPSharp Virtual Device";

    /// <summary>Device status word (attribute 5).</summary>
    public ushort Status { get; init; }
}
