namespace EipSim.Cip;

/// <summary>Device identity information used in ListIdentity responses and the Identity CIP object.</summary>
public sealed class IdentityInfo
{
    public const uint ClassCode = 0x01;

    public ushort VendorId { get; init; }
    public ushort DeviceType { get; init; }
    public ushort ProductCode { get; init; }
    public byte MajorRevision { get; init; }
    public byte MinorRevision { get; init; }
    public uint SerialNumber { get; init; }
    public string ProductName { get; init; } = "EipSim Virtual Device";
    public ushort Status { get; init; }
}
