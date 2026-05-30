using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Device;

/// <summary>
/// Standard (non-safety) EtherNet/IP device.
/// Uses Class 1 I/O framing with CIP sequence count and run/idle header.
/// </summary>
public sealed class StandardDevice : VirtualDevice
{
    public StandardDevice(IdentityInfo identity, IPAddress bindAddress, string? name = null)
        : base(identity, bindAddress, name) { }

    public StandardDevice(
        IdentityInfo identity,
        IPAddress bindAddress,
        CipDispatcher dispatcher,
        AssemblyObject assemblies,
        ConnectionManagerObject connectionManager,
        string? name = null,
        Func<IPEndPoint, IEipUdpTransport>? udpFactory = null,
        Func<ICipDispatch, IdentityInfo, IoEipAdapter>? adapterFactory = null)
        : base(identity, bindAddress, dispatcher, assemblies, connectionManager,
               name, udpFactory, adapterFactory) { }
}
