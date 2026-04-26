using System.Net;
using EipSim.Cip;

namespace EipSim.Device;

/// <summary>
/// CIP TCP/IP Interface Object (Class 0xF5). Required by EtherNet/IP devices.
/// Minimal implementation for Phase 1.
/// </summary>
public static class TcpIpInterfaceObject
{
    public const uint ClassCode = 0xF5;

    public static CipClass Create(IPAddress ipAddress)
    {
        var cls = new CipClass(ClassCode, "TCP/IP Interface", revision: 4);
        cls.AddStandardInstanceServices();
        var inst = cls.CreateInstance(1);

        // Attribute 1: Status (UDINT) — 0x01 = configured
        inst.AddAttribute(CipAttribute.Create(1, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, 1u));

        // Attribute 2: Configuration Capability (UDINT) — 0x04 = can config via DHCP
        inst.AddAttribute(CipAttribute.Create(2, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, 0x04u));

        // Attribute 3: Configuration Control (UDINT) — 0x02 = DHCP
        inst.AddAttribute(CipAttribute.Create(3, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, 0x02u));

        // Attribute 5: Interface Configuration (complex struct)
        // IP + subnet + gateway + DNS — encode as raw bytes
        var ifConfig = new byte[22]; // minimum
        var ipBytes = ipAddress.GetAddressBytes();
        ipBytes.CopyTo(ifConfig.AsSpan(0));
        // Subnet mask 255.255.255.0
        ifConfig[4] = 255; ifConfig[5] = 255; ifConfig[6] = 255; ifConfig[7] = 0;
        inst.AddAttribute(new CipAttribute(5, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, ifConfig));

        return cls;
    }
}
