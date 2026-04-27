namespace EipSim.Cip;

/// <summary>
/// Default ICipDispatch implementation that routes requests through the CIP object tree.
/// Walks: path.ClassId → CipClass → instance → service → handler.
/// If no match is found at the class/instance/service level, returns specific CIP error codes.
/// If the path has no ClassId (e.g. symbolic segment), calls <see cref="OnUnhandled"/>
/// which subclasses can override (e.g. LogixDispatcher handles symbolic tag names there).
/// </summary>
public class CipDispatcher : ICipDispatch
{
    /// <summary>Registered CIP classes keyed by class code.</summary>
    private readonly Dictionary<uint, CipClass> _classes = new();

    /// <summary>Register a CIP class so it can receive dispatched requests.</summary>
    public void RegisterClass(CipClass cipClass) => _classes[cipClass.ClassCode] = cipClass;

    /// <summary>Look up a registered class by class code. Returns null if not registered.</summary>
    public CipClass? GetClass(uint classCode) =>
        _classes.TryGetValue(classCode, out var cls) ? cls : null;

    /// <summary>All registered CIP classes.</summary>
    public IReadOnlyDictionary<uint, CipClass> RegisteredClasses => _classes;

    /// <summary>
    /// Route a CIP service request to the matching class, instance, and service handler.
    /// Returns appropriate CIP error codes when the path cannot be resolved:
    /// - No ClassId in path → OnUnhandled (for symbolic segment handling by subclasses)
    /// - Class not found → PathDestinationUnknown (0x05)
    /// - Instance not found → ObjectDoesNotExist (0x16)
    /// - Service not found → ServiceNotSupported (0x08)
    /// </summary>
    public CipServiceResponse Dispatch(byte serviceCode, CipPath path, ReadOnlyMemory<byte> data)
    {
        // No class in path — delegate to subclass (e.g. symbolic tag dispatch)
        if (path.ClassId == null)
            return OnUnhandled(serviceCode, path, data);

        // Class not registered
        if (!_classes.TryGetValue(path.ClassId.Value, out var cipClass))
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(CipStatus.PathDestinationUnknown));

        uint instanceId = path.InstanceId ?? 0;
        bool isClassLevel = instanceId == 0;

        // Instance not found
        var instance = cipClass.GetInstance(instanceId);
        if (instance == null)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(CipStatus.ObjectDoesNotExist));

        // Service not supported on this class
        var service = cipClass.GetService(serviceCode, isClassLevel);
        if (service == null)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(CipStatus.ServiceNotSupported));

        var request = new CipServiceRequest
        {
            ServiceCode = serviceCode,
            Path = path,
            Data = data,
        };

        return service.Handler(instance, request);
    }

    /// <summary>
    /// Called when the path has no ClassId (e.g. symbolic segment addressing).
    /// Override in subclasses to provide custom routing.
    /// Default returns PathDestinationUnknown.
    /// </summary>
    protected virtual CipServiceResponse OnUnhandled(byte serviceCode, CipPath path, ReadOnlyMemory<byte> data)
    {
        return CipServiceResponse.Error(serviceCode, CipStatus.Error(CipStatus.PathDestinationUnknown));
    }
}
