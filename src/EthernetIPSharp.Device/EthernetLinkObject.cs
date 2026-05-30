using System.Net;
using System.Net.NetworkInformation;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Device;

/// <summary>
/// CIP Ethernet Link Object (Class 0xF6). Required by EtherNet/IP devices.
/// Reports the real MAC address and link speed of the host NIC bound to the device.
/// </summary>
public static class EthernetLinkObject
{
    /// <summary>CIP class code for Ethernet Link.</summary>
    public const uint ClassCode = 0xF6;

    // Fallback values used when no matching NIC is found
    private static readonly byte[] FallbackMac = { 0x00, 0x1C, 0x2E, 0x00, 0x00, 0x01 };
    private const uint FallbackSpeedMbps = 1000;

    // Bit flags (UDINT attribute 2):
    //   bit 0: Link Status (1 = active)
    //   bit 1: Half/Full Duplex (1 = full)
    //   bit 2-4: Negotiation Status (4 = success and forced settings used)
    //   bit 5: Manual Setting Requires Reset
    //   bit 6: Local Hardware Fault
    // Default 0x0F = link active + full duplex + auto-negotiation
    private const uint DefaultFlags = 0x0F;

    /// <summary>
    /// Create an Ethernet Link CIP class. Queries the host NIC matching <paramref name="bindAddress"/>
    /// to report its real MAC and speed. If bindAddress is null or IPAddress.Any, the NIC carrying
    /// the default route is used. Falls back to placeholder values if no NIC matches.
    /// </summary>
    public static CipClass Create(IPAddress? bindAddress = null)
    {
        var (mac, speedMbps) = QueryNicInfo(bindAddress);

        var cls = new CipClass(ClassCode, "Ethernet Link", revision: 4);
        cls.AddStandardInstanceServices();
        var inst = cls.CreateInstance(1);

        // Attribute 1: Interface Speed (UDINT) in megabits per second
        inst.AddAttribute(CipAttribute.Create(1, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, speedMbps));

        // Attribute 2: Interface Flags (UDINT) — link active, full duplex, auto-neg
        inst.AddAttribute(CipAttribute.Create(2, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, DefaultFlags));

        // Attribute 3: Physical Address (6 bytes USINT array)
        inst.AddAttribute(new CipAttribute(3, CipDataType.Usint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, mac));

        return cls;
    }

    private static (byte[] mac, uint speedMbps) QueryNicInfo(IPAddress? bindAddress)
    {
        try
        {
            NetworkInterface? nic = null;

            bool bindIsAny = bindAddress is null
                || bindAddress.Equals(IPAddress.Any)
                || bindAddress.Equals(IPAddress.IPv6Any);

            if (!bindIsAny)
            {
                // Bind is a specific IP — find the NIC that owns it
                nic = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up
                        && n.GetIPProperties().UnicastAddresses
                            .Any(a => a.Address.Equals(bindAddress)));
            }

            // Bind is Any (or no match yet) — use the NIC that carries the default route.
            // A NIC has a default route if it has a non-zero gateway address.
            nic ??= NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                    && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                    && n.GetIPProperties().GatewayAddresses
                        .Any(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                            && !g.Address.Equals(IPAddress.Any)))
                .OrderBy(n => n.GetIPProperties().GetIPv4Properties()?.Index ?? int.MaxValue)
                .FirstOrDefault();

            if (nic is null) return (FallbackMac, FallbackSpeedMbps);

            var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
            if (macBytes.Length != 6) macBytes = FallbackMac;

            // NetworkInterface.Speed is in bits/sec; convert to Mbps. Some virtual adapters
            // report 0 or -1 — fall back in that case.
            long bps = nic.Speed;
            uint mbps = bps > 0 ? (uint)(bps / 1_000_000) : FallbackSpeedMbps;
            if (mbps == 0) mbps = FallbackSpeedMbps;

            return (macBytes, mbps);
        }
        catch
        {
            return (FallbackMac, FallbackSpeedMbps);
        }
    }
}
