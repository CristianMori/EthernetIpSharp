namespace EipSim.Cip;

/// <summary>
/// CIP Message Router (Class 0x02). Routes explicit message requests to the
/// appropriate CIP class, instance, and service handler.
/// </summary>
public sealed class MessageRouter
{
    public const uint ClassCode = 0x02;

    private readonly Dictionary<uint, CipClass> _classes = new();
    private readonly CipClass _routerClass;

    public MessageRouter()
    {
        _routerClass = new CipClass(ClassCode, "Message Router", revision: 1);
        _routerClass.AddStandardInstanceServices();
        var inst = _routerClass.CreateInstance(1);
        // No mandatory instance attributes beyond class-level
        RegisterClass(_routerClass);
    }

    public void RegisterClass(CipClass cipClass) => _classes[cipClass.ClassCode] = cipClass;

    public CipClass? GetClass(uint classCode) =>
        _classes.TryGetValue(classCode, out var cls) ? cls : null;

    public IReadOnlyDictionary<uint, CipClass> RegisteredClasses => _classes;

    /// <summary>
    /// Route an explicit message request to the target object and service.
    /// Parses the MR request format: service code (1) + path size in words (1) + path + data.
    /// </summary>
    public CipServiceResponse RouteRequest(ReadOnlySpan<byte> mrRequestData)
    {
        if (mrRequestData.Length < 2)
            return CipServiceResponse.Error(0, CipStatus.Error(CipStatus.NotEnoughData));

        byte serviceCode = mrRequestData[0];
        byte pathSizeWords = mrRequestData[1];
        int pathSizeBytes = pathSizeWords * 2;

        if (mrRequestData.Length < 2 + pathSizeBytes)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(CipStatus.NotEnoughData));

        var pathSpan = mrRequestData.Slice(2, pathSizeBytes);
        var (path, _) = CipPath.Parse(pathSpan);

        var requestData = mrRequestData.Length > 2 + pathSizeBytes
            ? mrRequestData.Slice(2 + pathSizeBytes).ToArray()
            : Array.Empty<byte>();

        return RouteRequest(new CipServiceRequest
        {
            ServiceCode = serviceCode,
            Path = path,
            Data = requestData,
        });
    }

    public CipServiceResponse RouteRequest(CipServiceRequest request)
    {
        if (request.Path.ClassId == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.PathSegmentError));

        if (!_classes.TryGetValue(request.Path.ClassId.Value, out var cipClass))
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.PathDestinationUnknown));

        uint instanceId = request.Path.InstanceId ?? 0;
        bool isClassLevel = instanceId == 0;

        var instance = cipClass.GetInstance(instanceId);
        if (instance == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.ObjectDoesNotExist));

        var service = cipClass.GetService(request.ServiceCode, isClassLevel);
        if (service == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.ServiceNotSupported));

        return service.Handler(instance, request);
    }
}
