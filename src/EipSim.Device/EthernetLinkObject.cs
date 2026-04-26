using EipSim.Cip;

namespace EipSim.Device;

/// <summary>
/// CIP Ethernet Link Object (Class 0xF6). Required by EtherNet/IP devices.
/// Minimal implementation for Phase 1.
/// </summary>
public static class EthernetLinkObject
{
    public const uint ClassCode = 0xF6;

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

        // Attribute 3: Physical Address (6 bytes MAC)
        var mac = new byte[] { 0x00, 0x1C, 0x2E, 0x00, 0x00, 0x01 };
        inst.AddAttribute(new CipAttribute(3, CipDataType.Usint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, mac));

        return cls;
    }
}
