namespace EipSim.Cip;

/// <summary>
/// Default ICipDispatch implementation that routes requests through the CIP object tree.
/// Walks: path.ClassId → CipClass → instance → service → handler.
/// If no match is found, calls <see cref="OnUnhandled"/> which subclasses can override
/// to provide custom handling (e.g. forwarding, bridging, application-specific logic).
/// </summary>
public class CipDispatcher : ICipDispatch
{
    private readonly Dictionary<uint, CipClass> _classes = new();

    public void RegisterClass(CipClass cipClass) => _classes[cipClass.ClassCode] = cipClass;

    public CipClass? GetClass(uint classCode) =>
        _classes.TryGetValue(classCode, out var cls) ? cls : null;

    public IReadOnlyDictionary<uint, CipClass> RegisteredClasses => _classes;

    public CipServiceResponse Dispatch(byte serviceCode, CipPath path, ReadOnlyMemory<byte> data)
    {
        if (path.ClassId == null)
            return OnUnhandled(serviceCode, path, data);

        if (!_classes.TryGetValue(path.ClassId.Value, out var cipClass))
            return OnUnhandled(serviceCode, path, data);

        uint instanceId = path.InstanceId ?? 0;
        bool isClassLevel = instanceId == 0;

        var instance = cipClass.GetInstance(instanceId);
        if (instance == null)
            return OnUnhandled(serviceCode, path, data);

        var service = cipClass.GetService(serviceCode, isClassLevel);
        if (service == null)
            return OnUnhandled(serviceCode, path, data);

        var request = new CipServiceRequest
        {
            ServiceCode = serviceCode,
            Path = path,
            Data = data,
        };

        return service.Handler(instance, request);
    }

    /// <summary>
    /// Called when no registered CIP class/instance/service matches the request.
    /// Override in subclasses to provide custom handling.
    /// Default returns PathDestinationUnknown.
    /// </summary>
    protected virtual CipServiceResponse OnUnhandled(byte serviceCode, CipPath path, ReadOnlyMemory<byte> data)
    {
        return CipServiceResponse.Error(serviceCode, CipStatus.Error(CipStatus.PathDestinationUnknown));
    }
}
