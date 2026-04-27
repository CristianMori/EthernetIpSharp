namespace EipSim.Cip;

/// <summary>
/// Flags controlling which CIP services can access an attribute.
/// </summary>
[Flags]
public enum AttributeAccess : byte
{
    /// <summary>No access permitted.</summary>
    None = 0,
    /// <summary>Readable via GetAttributeSingle (0x0E).</summary>
    GetSingle = 1,
    /// <summary>Writable via SetAttributeSingle (0x10).</summary>
    SetSingle = 2,
    /// <summary>Included in GetAttributeAll (0x01) response.</summary>
    GetAll = 4,
    /// <summary>Full access — readable, writable, included in GetAll.</summary>
    All = GetSingle | SetSingle | GetAll,
}

/// <summary>
/// A single CIP attribute — a typed, access-controlled value identified by numeric ID.
/// Attributes belong to a CipInstance and are read/written via standard CIP services.
/// The data is stored as a raw byte array in wire format (little-endian).
///
/// Subclassable — AssemblyDataAttribute overrides to back the attribute with a live I/O buffer.
/// </summary>
public class CipAttribute
{
    /// <summary>Attribute ID within the owning instance.</summary>
    public ushort Id { get; }

    /// <summary>CIP data type of this attribute (informational — not enforced on read/write).</summary>
    public CipDataType DataType { get; }

    /// <summary>Access flags controlling which services can read/write this attribute.</summary>
    public AttributeAccess Access { get; }

    /// <summary>Raw attribute data in wire format.</summary>
    private byte[] _data;

    /// <summary>
    /// Create an attribute with the given ID, type, access, and initial data.
    /// The data array is stored by reference — caller should not modify it after construction.
    /// </summary>
    public CipAttribute(ushort id, CipDataType dataType, AttributeAccess access, byte[] initialData)
    {
        Id = id;
        DataType = dataType;
        Access = access;
        _data = initialData;
    }

    /// <summary>Read-only view of the attribute data.</summary>
    public ReadOnlySpan<byte> Data => _data;

    /// <summary>Length of the attribute data in bytes.</summary>
    public int DataLength => _data.Length;

    /// <summary>
    /// Replace the attribute data. If the new data has a different length,
    /// the internal buffer is reallocated. This may detach subclass-provided buffers
    /// (e.g. AssemblyDataAttribute) — use with care.
    /// </summary>
    public void SetData(ReadOnlySpan<byte> value)
    {
        if (value.Length != _data.Length)
            _data = new byte[value.Length];
        value.CopyTo(_data);
    }

    /// <summary>
    /// Encode this attribute's data into a destination buffer.
    /// Returns the number of bytes written (equal to DataLength).
    /// The destination must be at least DataLength bytes.
    /// </summary>
    public int EncodeTo(Span<byte> dst)
    {
        _data.CopyTo(dst);
        return _data.Length;
    }

    // --- Convenience factory methods ---

    /// <summary>Create a 1-byte attribute (BOOL, SINT, USINT).</summary>
    public static CipAttribute Create(ushort id, CipDataType type, AttributeAccess access, byte value)
    {
        return new CipAttribute(id, type, access, [value]);
    }

    /// <summary>Create a 2-byte attribute (INT, UINT, WORD) in little-endian.</summary>
    public static CipAttribute Create(ushort id, CipDataType type, AttributeAccess access, ushort value)
    {
        var data = new byte[2];
        CipDataSerializer.WriteUint(data, value);
        return new CipAttribute(id, type, access, data);
    }

    /// <summary>Create a 4-byte attribute (DINT, UDINT, DWORD) in little-endian.</summary>
    public static CipAttribute Create(ushort id, CipDataType type, AttributeAccess access, uint value)
    {
        var data = new byte[4];
        CipDataSerializer.WriteUdint(data, value);
        return new CipAttribute(id, type, access, data);
    }

    /// <summary>Create a SHORT_STRING attribute (1-byte length + ASCII chars).</summary>
    public static CipAttribute CreateShortString(ushort id, AttributeAccess access, string value)
    {
        var data = new byte[1 + value.Length];
        CipDataSerializer.WriteShortString(data, value);
        return new CipAttribute(id, CipDataType.ShortString, access, data);
    }
}
