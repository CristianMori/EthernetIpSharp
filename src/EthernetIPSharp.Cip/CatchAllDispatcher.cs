namespace EthernetIPSharp.Cip;

/// <summary>
/// View of an incoming CIP request that didn't match any registered class.
/// Field references are valid for the duration of the handler call.
/// </summary>
public readonly struct CatchAllRequest
{
    public byte                  ServiceCode { get; init; }
    public CipPath               Path        { get; init; }
    public ReadOnlyMemory<byte>  Data        { get; init; }
}

/// <summary>
/// What a CatchAllDispatcher handler returns. Leave <see cref="Data"/> empty
/// to send a reply with no payload. Set <see cref="Status"/> non-zero to
/// indicate an error (Status == 0 = Success).
/// </summary>
public sealed class CatchAllReply
{
    public byte[] Data   { get; init; } = Array.Empty<byte>();
    public byte   Status { get; init; } = 0;
}

/// <summary>
/// CipDispatcher subclass that routes every otherwise-unmatched request
/// through a user-supplied handler. Useful for echo servers, sniffers, and
/// adapters that want a single fall-through hook without subclassing.
///
/// Classes registered via <see cref="CipDispatcher.RegisterClass"/> still go
/// through the standard class → instance → service routing; only requests
/// that fall through to <see cref="OnUnhandled"/> hit the handler.
/// </summary>
public sealed class CatchAllDispatcher : CipDispatcher
{
    /// <summary>Handler shape — receives the request, returns the reply.</summary>
    public delegate CatchAllReply Handler(in CatchAllRequest request);

    private Handler? _handler;

    /// <summary>Install (or replace) the catch-all handler. Without a handler the
    /// dispatcher behaves like the base CipDispatcher and returns the
    /// would-have-been error status.</summary>
    public void SetHandler(Handler h) => _handler = h;

    protected override CipServiceResponse OnUnhandled(byte serviceCode, CipPath path,
        ReadOnlyMemory<byte> data, byte defaultStatus = CipStatus.PathDestinationUnknown)
    {
        if (_handler == null)
            return base.OnUnhandled(serviceCode, path, data, defaultStatus);

        var req = new CatchAllRequest { ServiceCode = serviceCode, Path = path, Data = data };
        var reply = _handler(req);
        if (reply.Status != 0)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(reply.Status));
        return CipServiceResponse.Success(serviceCode, reply.Data);
    }
}
