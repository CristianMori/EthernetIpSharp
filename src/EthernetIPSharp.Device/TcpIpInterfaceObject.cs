using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Device;

/// <summary>
/// CIP TCP/IP Interface Object (Class 0xF5). Required by EtherNet/IP devices.
/// Minimal implementation — provides enough attributes for PLC discovery and connection.
/// </summary>
public static class TcpIpInterfaceObject
{
    /// <summary>CIP class code for TCP/IP Interface.</summary>
    public const uint ClassCode = 0xF5;

    /// <summary>
    /// Create a TCP/IP Interface CIP class with instance 1 configured for the given IP address.
    /// Attributes 1-3 and 5 are populated. Attribute 4 (Physical Link Object) is optional and omitted.
    /// </summary>
    public static CipClass Create(IPAddress ipAddress)
    {
        var cls = new CipClass(ClassCode, "TCP/IP Interface", revision: 4);
        cls.AddStandardInstanceServices();
        var inst = cls.CreateInstance(1);

        // Attribute 1: Status (UDINT) — 0x01 = interface configured
        inst.AddAttribute(CipAttribute.Create(1, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, 1u));

        // Attribute 2: Configuration Capability (UDINT) — 0x04 = DHCP capable
        inst.AddAttribute(CipAttribute.Create(2, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, 0x04u));

        // Attribute 3: Configuration Control (UDINT) — 0x02 = DHCP enabled
        inst.AddAttribute(CipAttribute.Create(3, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, 0x02u));

        // Attribute 4: Physical Link Object — optional, omitted

        // Attribute 5: Interface Configuration (struct: IP + subnet + gateway + name server + domain)
        // Encoded as raw bytes — minimum 22 bytes for IP(4) + subnet(4) + gateway(4) + DNS1(4) + DNS2(4) + domain length(2)
        var ifConfig = new byte[22];
        ipAddress.GetAddressBytes().CopyTo(ifConfig.AsSpan(0)); // IP address
        ifConfig[4] = 255; ifConfig[5] = 255; ifConfig[6] = 255; ifConfig[7] = 0; // Subnet 255.255.255.0
        // Gateway, DNS, domain — all zeroed (defaults)
        inst.AddAttribute(new CipAttribute(5, CipDataType.Byte,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, ifConfig));

        return cls;
    }
}
