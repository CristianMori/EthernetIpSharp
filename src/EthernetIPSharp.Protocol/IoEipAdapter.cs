using System.Net;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// EipAdapter variant for Class 0/1 I/O serving — attaches Sockaddr Info
/// O→T / T→O items to Forward Open replies so the originator knows which
/// UDP endpoint to use, and fires <see cref="ConnectionOpened"/> so the host
/// can associate the new IoConnection with its PLC's UDP endpoint. Skips the
/// Sockaddr items for Class 3 explicit FwdOpens (those don't use UDP, and
/// Logix MSG rejects the reply with extended status 0x0205).
/// </summary>
public sealed class IoEipAdapter : EipAdapter
{
    /// <summary>UDP port advertised in Forward Open Sockaddr Info items (default 2222).</summary>
    public int UdpPort { get; set; } = EipUdpTransport.IoPort;

    /// <summary>
    /// Fired when a successful Forward Open response is about to be sent on a
    /// non-Class-3 connection. Parameters: CIP service response, remote scanner
    /// UDP endpoint. Used by VirtualDevice to set RemoteEndpoint on the new
    /// IoConnection.
    /// </summary>
    public event Action<CipServiceResponse, IPEndPoint>? ConnectionOpened;

    public IoEipAdapter(ICipDispatch dispatch, IdentityInfo identity,
                          ICipDispatch? identitySource = null)
        : base(dispatch, identity, identitySource) { }

    public IoEipAdapter(ICipDispatch dispatch, IdentityInfo identity,
                          ISessionManager sessions, ICipDispatch? identitySource = null)
        : base(dispatch, identity, sessions, identitySource) { }

    protected override void OnForwardOpenReply(List<CpfItem> cpfItems, byte serviceCode,
        ReadOnlyMemory<byte> requestData, CipServiceResponse response,
        IPEndPoint localEp, IPEndPoint remoteEp)
    {
        // Class 3 explicit-messaging FwdOpens don't use UDP; including Sockaddr
        // Info items in the reply makes Logix's MSG instruction reject the
        // connection (extended status 0x0205). Peek the transport_class_trigger
        // byte to skip Class 3.
        int tctOff = serviceCode == 0x5B ? 36 : 34;
        var data = requestData.Span;
        if (data.Length > tctOff && (data[tctOff] & 0x0F) == 3)
            return;

        cpfItems.Add(new CpfItem { TypeId = CpfItemType.SockaddrInfoOtoT, Data = BuildSockaddrInfo(localEp.Address, UdpPort) });
        cpfItems.Add(new CpfItem { TypeId = CpfItemType.SockaddrInfoTtoO, Data = BuildSockaddrInfo(localEp.Address, UdpPort) });

        var plcUdpEndpoint = new IPEndPoint(remoteEp.Address, EipUdpTransport.IoPort);
        ConnectionOpened?.Invoke(response, plcUdpEndpoint);
    }
}
