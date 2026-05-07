using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Device;

/// <summary>
/// CIP Ethernet Link Object (Class 0xF6). Required by EtherNet/IP devices.
/// Minimal implementation — provides link speed, flags, and a placeholder MAC address.
/// </summary>
public static class EthernetLinkObject
{
    /// <summary>CIP class code for Ethernet Link.</summary>
    public const uint ClassCode = 0xF6;

    /// <summary>
    /// Create an Ethernet Link CIP class with instance 1.
    /// Attributes: interface speed, flags, and physical address (placeholder MAC).
    /// </summary>
    public static CipClass Create()
    {
        var cls = new CipClass(ClassCode, "Ethernet Link", revision: 4);
        cls.AddStandardInstanceServices();
        var inst = cls.CreateInstance(1);

        // Attribute 1: Interface Speed (UDINT) — 100 Mbps
        inst.AddAttribute(CipAttribute.Create(1, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, 100u));

        // Attribute 2: Interface Flags (UDINT) — link active, full duplex, auto-negotiate
        inst.AddAttribute(CipAttribute.Create(2, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, 0x0Fu));

        // Attribute 3: Physical Address (6 bytes) — placeholder MAC address
        var mac = new byte[] { 0x00, 0x1C, 0x2E, 0x00, 0x00, 0x01 };
        inst.AddAttribute(new CipAttribute(3, CipDataType.Usint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, mac));

        return cls;
    }
}
