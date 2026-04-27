namespace EipSim.Cip;

/// <summary>
/// Represents a single instance of a CIP class.
/// Each instance holds a set of attributes identified by numeric ID.
/// Instance 0 is reserved for class-level attributes (managed by CipClass).
/// </summary>
public class CipInstance
{
    /// <summary>Attribute storage keyed by attribute ID.</summary>
    private readonly Dictionary<ushort, CipAttribute> _attributes = new();

    /// <summary>Cached sorted attribute list for GetAttributeAll. Invalidated on add.</summary>
    private CipAttribute[]? _sortedGetAllCache;

    /// <summary>The instance number. 0 = class-level instance.</summary>
    public uint InstanceId { get; }

    /// <summary>Back-reference to the CipClass that owns this instance.</summary>
    public CipClass? OwnerClass { get; internal set; }

    /// <summary>
    /// Application-specific data attached to this instance.
    /// Used to associate domain objects (e.g. Tag, AssemblyInstance) with CIP instances
    /// without coupling the CIP layer to application types.
    /// </summary>
    public object? UserData { get; set; }

    public CipInstance(uint instanceId)
    {
        InstanceId = instanceId;
    }

    /// <summary>Add or replace an attribute on this instance. Invalidates the GetAll cache.</summary>
    public void AddAttribute(CipAttribute attr)
    {
        _attributes[attr.Id] = attr;
        _sortedGetAllCache = null;
    }

    /// <summary>Look up an attribute by ID. Returns null if not found.</summary>
    public CipAttribute? GetAttribute(ushort id) =>
        _attributes.TryGetValue(id, out var attr) ? attr : null;

    /// <summary>All attributes on this instance (unordered).</summary>
    public IEnumerable<CipAttribute> Attributes => _attributes.Values;

    /// <summary>Number of attributes on this instance.</summary>
    public int AttributeCount => _attributes.Count;

    /// <summary>
    /// Encode all attributes that have the GetAll access flag, sorted by attribute ID.
    /// Used by the GetAttributeAll (0x01) service response.
    /// Sorted list is cached and only rebuilt when attributes change.
    /// </summary>
    public int EncodeAllAttributes(Span<byte> dst)
    {
        var sorted = _sortedGetAllCache ??= BuildGetAllCache();

        int offset = 0;
        foreach (var attr in sorted)
        {
            offset += attr.EncodeTo(dst.Slice(offset));
        }
        return offset;
    }

    private CipAttribute[] BuildGetAllCache()
    {
        return _attributes
            .Where(kv => (kv.Value.Access & AttributeAccess.GetAll) != 0)
            .OrderBy(kv => kv.Key)
            .Select(kv => kv.Value)
            .ToArray();
    }
}
