namespace EipSim.Cip;

[Flags]
public enum AttributeAccess : byte
{
    None = 0,
    GetSingle = 1,
    SetSingle = 2,
    GetAll = 4,
    All = GetSingle | SetSingle | GetAll,
}

public class CipAttribute
{
    public ushort Id { get; }
    public CipDataType DataType { get; }
    public AttributeAccess Access { get; }

    private byte[] _data;

    public CipAttribute(ushort id, CipDataType dataType, AttributeAccess access, byte[] initialData)
    {
        Id = id;
        DataType = dataType;
        Access = access;
        _data = initialData;
    }

    public ReadOnlySpan<byte> Data => _data;
    public int DataLength => _data.Length;

    public void SetData(ReadOnlySpan<byte> value)
    {
        if (value.Length != _data.Length)
            _data = new byte[value.Length];
        value.CopyTo(_data);
    }

    public int EncodeTo(Span<byte> dst)
    {
        _data.CopyTo(dst);
        return _data.Length;
    }

    // Convenience factory methods
    public static CipAttribute Create(ushort id, CipDataType type, AttributeAccess access, byte value)
    {
        return new CipAttribute(id, type, access, [value]);
    }

    public static CipAttribute Create(ushort id, CipDataType type, AttributeAccess access, ushort value)
    {
        var data = new byte[2];
        CipDataSerializer.WriteUint(data, value);
        return new CipAttribute(id, type, access, data);
    }

    public static CipAttribute Create(ushort id, CipDataType type, AttributeAccess access, uint value)
    {
        var data = new byte[4];
        CipDataSerializer.WriteUdint(data, value);
        return new CipAttribute(id, type, access, data);
    }

    public static CipAttribute CreateShortString(ushort id, AttributeAccess access, string value)
    {
        var data = new byte[1 + value.Length];
        CipDataSerializer.WriteShortString(data, value);
        return new CipAttribute(id, CipDataType.ShortString, access, data);
    }
}
