namespace EipSim.Cip;

/// <summary>
/// Represents a CIP class (object type) in the CIP object model.
/// A class holds a set of instances, each with their own attributes.
/// Services are registered at two levels:
/// - Class-level services: handle requests to instance 0 (the class itself).
/// - Instance-level services: shared by all instances of this class.
///
/// Per the CIP spec, instance 0 (ClassInstance) holds class-level attributes
/// such as revision and max instance count.
/// </summary>
public class CipClass
{
    /// <summary>All instances of this class, keyed by instance ID (excludes instance 0).</summary>
    private readonly Dictionary<uint, CipInstance> _instances = new();

    /// <summary>Tracks the highest instance ID for class attribute 2 (max instance).</summary>
    private uint _maxInstanceId;

    /// <summary>Services available on instances of this class.</summary>
    private readonly Dictionary<byte, CipServiceDefinition> _instanceServices = new();

    /// <summary>Services available on the class itself (instance 0).</summary>
    private readonly Dictionary<byte, CipServiceDefinition> _classServices = new();

    /// <summary>The CIP class code (e.g. 0x01 = Identity, 0x04 = Assembly, 0x6B = Symbol).</summary>
    public uint ClassCode { get; }

    /// <summary>Human-readable name for this class.</summary>
    public string Name { get; }

    /// <summary>
    /// Instance 0 — the class-level instance per CIP spec.
    /// Holds class attributes such as revision (attr 1) and max instance ID (attr 2).
    /// </summary>
    public CipInstance ClassInstance { get; }

    /// <summary>
    /// Create a CIP class with the given class code, name, and revision.
    /// Automatically creates instance 0 with standard class-level attributes
    /// and registers GetAttributeSingle and GetAttributeAll class-level services.
    /// </summary>
    public CipClass(uint classCode, string name, ushort revision = 1)
    {
        ClassCode = classCode;
        Name = name;
        ClassInstance = new CipInstance(0) { OwnerClass = this };

        // Standard class-level attributes
        ClassInstance.AddAttribute(CipAttribute.Create(1, CipDataType.Uint, AttributeAccess.GetSingle | AttributeAccess.GetAll, revision));
        ClassInstance.AddAttribute(CipAttribute.Create(2, CipDataType.Uint, AttributeAccess.GetSingle | AttributeAccess.GetAll, (ushort)0)); // max instance — updated dynamically

        // Register standard class-level services
        AddClassService(new CipServiceDefinition(CipStandardServices.GetAttributeSingle, "Get_Attribute_Single", CipStandardServices.HandleGetAttributeSingle));
        AddClassService(new CipServiceDefinition(CipStandardServices.GetAttributeAll, "Get_Attributes_All", CipStandardServices.HandleGetAttributeAll));
    }

    /// <summary>
    /// Create a new instance with the given ID and add it to this class.
    /// Updates the max instance class attribute (attr 2).
    /// </summary>
    public CipInstance CreateInstance(uint instanceId)
    {
        var instance = new CipInstance(instanceId) { OwnerClass = this };
        _instances[instanceId] = instance;
        UpdateMaxInstance(instanceId);
        return instance;
    }

    /// <summary>
    /// Add an existing instance to this class.
    /// Sets the instance's OwnerClass to this class.
    /// Updates the max instance class attribute (attr 2).
    /// </summary>
    public void AddInstance(CipInstance instance)
    {
        instance.OwnerClass = this;
        _instances[instance.InstanceId] = instance;
        UpdateMaxInstance(instance.InstanceId);
    }

    /// <summary>
    /// Update the max instance class attribute if the given ID exceeds the current max.
    /// O(1) — no scanning of all instance IDs.
    /// </summary>
    private void UpdateMaxInstance(uint instanceId)
    {
        if (instanceId <= _maxInstanceId) return;
        _maxInstanceId = instanceId;

        var attr = ClassInstance.GetAttribute(2);
        if (attr != null)
        {
            Span<byte> buf = stackalloc byte[2];
            CipDataSerializer.WriteUint(buf, (ushort)_maxInstanceId);
            attr.SetData(buf);
        }
    }

    /// <summary>
    /// Look up an instance by ID.
    /// Instance 0 returns the ClassInstance (class-level attributes).
    /// Returns null if the instance does not exist.
    /// </summary>
    public CipInstance? GetInstance(uint instanceId) =>
        instanceId == 0 ? ClassInstance :
        _instances.TryGetValue(instanceId, out var inst) ? inst : null;

    /// <summary>All instances of this class (excludes instance 0).</summary>
    public IReadOnlyDictionary<uint, CipInstance> Instances => _instances;

    /// <summary>Register a service available on all instances of this class.</summary>
    public void AddInstanceService(CipServiceDefinition service) =>
        _instanceServices[service.ServiceCode] = service;

    /// <summary>Look up an instance-level service by service code.</summary>
    public CipServiceDefinition? GetInstanceService(byte serviceCode) =>
        _instanceServices.TryGetValue(serviceCode, out var svc) ? svc : null;

    /// <summary>Register a service available on the class itself (instance 0).</summary>
    public void AddClassService(CipServiceDefinition service) =>
        _classServices[service.ServiceCode] = service;

    /// <summary>Look up a class-level service by service code.</summary>
    public CipServiceDefinition? GetClassService(byte serviceCode) =>
        _classServices.TryGetValue(serviceCode, out var svc) ? svc : null;

    /// <summary>
    /// Look up a service by code, choosing class-level or instance-level
    /// based on whether the request targets instance 0.
    /// </summary>
    public CipServiceDefinition? GetService(byte serviceCode, bool isClassLevel) =>
        isClassLevel ? GetClassService(serviceCode) : GetInstanceService(serviceCode);

    /// <summary>
    /// Convenience method to register the standard CIP instance services:
    /// GetAttributeSingle (0x0E), SetAttributeSingle (0x10), GetAttributeAll (0x01).
    /// </summary>
    public void AddStandardInstanceServices()
    {
        AddInstanceService(new CipServiceDefinition(CipStandardServices.GetAttributeSingle, "Get_Attribute_Single", CipStandardServices.HandleGetAttributeSingle));
        AddInstanceService(new CipServiceDefinition(CipStandardServices.SetAttributeSingle, "Set_Attribute_Single", CipStandardServices.HandleSetAttributeSingle));
        AddInstanceService(new CipServiceDefinition(CipStandardServices.GetAttributeAll, "Get_Attributes_All", CipStandardServices.HandleGetAttributeAll));
    }
}
