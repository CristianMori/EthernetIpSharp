using EipSim.Cip;

namespace EipSim.Device;

/// <summary>
/// CIP Assembly Object (Class 0x04).
/// Each instance holds a byte array buffer representing I/O data.
/// Attribute 3 (Data) is the assembly data — read/write via standard CIP services.
/// </summary>
public sealed class AssemblyObject
{
    public const uint ClassCode = 0x04;
    public const ushort DataAttributeId = 3;

    private readonly CipClass _cipClass;
    private readonly Dictionary<uint, AssemblyInstance> _assemblies = new();

    public CipClass CipClass => _cipClass;

    public AssemblyObject()
    {
        _cipClass = new CipClass(ClassCode, "Assembly", revision: 2);
        _cipClass.AddStandardInstanceServices();
    }

    /// <summary>Create an assembly instance with a fixed-size data buffer.</summary>
    public AssemblyInstance AddInstance(uint instanceId, int dataSize, string? name = null)
    {
        var assembly = new AssemblyInstance(instanceId, dataSize, name);
        _assemblies[instanceId] = assembly;

        var inst = _cipClass.CreateInstance(instanceId);

        // Attribute 1: Number of members (UINT) — 0 for raw data assemblies
        inst.AddAttribute(CipAttribute.Create(1, CipDataType.Uint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, (ushort)0));

        // Attribute 2: Assembly member list (empty for raw)
        inst.AddAttribute(new CipAttribute(2, CipDataType.Uint,
            AttributeAccess.GetSingle, []));

        // Attribute 3: Data — the actual I/O buffer
        // We use a custom attribute backed by the pinned buffer
        var dataAttr = new AssemblyDataAttribute(assembly);
        inst.AddAttribute(dataAttr);

        // Attribute 4: Size (UINT)
        inst.AddAttribute(CipAttribute.Create(4, CipDataType.Uint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, (ushort)dataSize));

        inst.UserData = assembly;

        return assembly;
    }

    public AssemblyInstance? GetAssembly(uint instanceId) =>
        _assemblies.TryGetValue(instanceId, out var asm) ? asm : null;

    public IReadOnlyDictionary<uint, AssemblyInstance> Assemblies => _assemblies;
}

/// <summary>
/// An assembly instance holding a pinned byte buffer for zero-copy I/O access.
/// </summary>
public sealed class AssemblyInstance
{
    private readonly byte[] _data;
    private readonly object _writeLock = new();

    public uint InstanceId { get; }
    public int DataSize { get; }
    public string? Name { get; }

    /// <summary>Fires on the thread that wrote new data (typically UDP receive thread).</summary>
    public event Action<uint, ReadOnlyMemory<byte>>? DataChanged;

    public AssemblyInstance(uint instanceId, int dataSize, string? name = null)
    {
        InstanceId = instanceId;
        DataSize = dataSize;
        Name = name;
        _data = new byte[dataSize];
    }

    /// <summary>Read the current assembly data. Safe for concurrent reads.</summary>
    public ReadOnlySpan<byte> GetData() => _data;

    /// <summary>Copy current data into a caller-owned buffer.</summary>
    public void CopyDataTo(Span<byte> destination) => _data.AsSpan().CopyTo(destination);

    /// <summary>Get the underlying buffer for direct UDP send (no copy).</summary>
    internal byte[] GetRawBuffer() => _data;

    /// <summary>Write new data into the assembly buffer.</summary>
    public void SetData(ReadOnlySpan<byte> source)
    {
        lock (_writeLock)
        {
            source.Slice(0, Math.Min(source.Length, _data.Length)).CopyTo(_data);
        }
        DataChanged?.Invoke(InstanceId, _data);
    }

    /// <summary>Write a typed value at a byte offset.</summary>
    public void Write<T>(int byteOffset, T value) where T : unmanaged
    {
        lock (_writeLock)
        {
            System.Runtime.CompilerServices.Unsafe.WriteUnaligned(
                ref _data[byteOffset], value);
        }
    }

    /// <summary>Read a typed value at a byte offset.</summary>
    public T Read<T>(int byteOffset) where T : unmanaged
    {
        return System.Runtime.CompilerServices.Unsafe.ReadUnaligned<T>(
            ref _data[byteOffset]);
    }
}

/// <summary>
/// Custom CipAttribute that reads/writes directly from/to the AssemblyInstance buffer.
/// </summary>
internal sealed class AssemblyDataAttribute : CipAttribute
{
    private readonly AssemblyInstance _assembly;

    public AssemblyDataAttribute(AssemblyInstance assembly)
        : base(AssemblyObject.DataAttributeId, CipDataType.Byte,
               AttributeAccess.GetSingle | AttributeAccess.SetSingle | AttributeAccess.GetAll,
               assembly.GetRawBuffer())
    {
        _assembly = assembly;
    }
}
