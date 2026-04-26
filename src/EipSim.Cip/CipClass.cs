namespace EipSim.Cip;

public class CipClass
{
    private readonly Dictionary<uint, CipInstance> _instances = new();
    private readonly Dictionary<byte, CipServiceDefinition> _instanceServices = new();
    private readonly Dictionary<byte, CipServiceDefinition> _classServices = new();

    public uint ClassCode { get; }
    public string Name { get; }

    /// <summary>Instance 0 — class-level attributes per CIP spec.</summary>
    public CipInstance ClassInstance { get; }

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

    public CipInstance CreateInstance(uint instanceId)
    {
        var instance = new CipInstance(instanceId) { OwnerClass = this };
        _instances[instanceId] = instance;
        // Update max instance class attribute
        var maxInst = ClassInstance.GetAttribute(2);
        if (maxInst != null)
        {
            var data = new byte[2];
            CipDataSerializer.WriteUint(data, (ushort)_instances.Keys.Max());
            maxInst.SetData(data);
        }
        return instance;
    }

    public void AddInstance(CipInstance instance)
    {
        instance.OwnerClass = this;
        _instances[instance.InstanceId] = instance;
    }

    public CipInstance? GetInstance(uint instanceId) =>
        instanceId == 0 ? ClassInstance :
        _instances.TryGetValue(instanceId, out var inst) ? inst : null;

    public IReadOnlyDictionary<uint, CipInstance> Instances => _instances;

    // Instance-level services (shared by all instances of this class)
    public void AddInstanceService(CipServiceDefinition service) =>
        _instanceServices[service.ServiceCode] = service;

    public CipServiceDefinition? GetInstanceService(byte serviceCode) =>
        _instanceServices.TryGetValue(serviceCode, out var svc) ? svc : null;

    // Class-level services
    public void AddClassService(CipServiceDefinition service) =>
        _classServices[service.ServiceCode] = service;

    public CipServiceDefinition? GetClassService(byte serviceCode) =>
        _classServices.TryGetValue(serviceCode, out var svc) ? svc : null;

    public CipServiceDefinition? GetService(byte serviceCode, bool isClassLevel) =>
        isClassLevel ? GetClassService(serviceCode) : GetInstanceService(serviceCode);

    /// <summary>Register standard Get/Set attribute services on instances.</summary>
    public void AddStandardInstanceServices()
    {
        AddInstanceService(new CipServiceDefinition(CipStandardServices.GetAttributeSingle, "Get_Attribute_Single", CipStandardServices.HandleGetAttributeSingle));
        AddInstanceService(new CipServiceDefinition(CipStandardServices.SetAttributeSingle, "Set_Attribute_Single", CipStandardServices.HandleSetAttributeSingle));
        AddInstanceService(new CipServiceDefinition(CipStandardServices.GetAttributeAll, "Get_Attributes_All", CipStandardServices.HandleGetAttributeAll));
    }
}
