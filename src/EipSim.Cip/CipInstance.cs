namespace EipSim.Cip;

public class CipInstance
{
    private readonly Dictionary<ushort, CipAttribute> _attributes = new();

    public uint InstanceId { get; }
    public CipClass? OwnerClass { get; internal set; }

    /// <summary>Arbitrary data attached to this instance for application use.</summary>
    public object? UserData { get; set; }

    public CipInstance(uint instanceId)
    {
        InstanceId = instanceId;
    }

    public void AddAttribute(CipAttribute attr) => _attributes[attr.Id] = attr;

    public CipAttribute? GetAttribute(ushort id) =>
        _attributes.TryGetValue(id, out var attr) ? attr : null;

    public IEnumerable<CipAttribute> Attributes => _attributes.Values;
    public int AttributeCount => _attributes.Count;

    /// <summary>Encode all gettable attributes in ID order for GetAttributeAll.</summary>
    public int EncodeAllAttributes(Span<byte> dst)
    {
        int offset = 0;
        foreach (var attr in _attributes.OrderBy(kv => kv.Key).Select(kv => kv.Value))
        {
            if ((attr.Access & AttributeAccess.GetAll) != 0)
            {
                offset += attr.EncodeTo(dst.Slice(offset));
            }
        }
        return offset;
    }
}
