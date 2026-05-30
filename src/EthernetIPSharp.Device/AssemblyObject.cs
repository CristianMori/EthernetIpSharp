using System.Runtime.CompilerServices;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Device;

/// <summary>
/// CIP Assembly Object (Class 0x04).
/// Each instance holds a byte array buffer representing I/O data.
/// Attribute 3 (Data) is the assembly data — read/write via standard CIP services.
/// </summary>
public sealed class AssemblyObject
{
    /// <summary>CIP class code for Assembly.</summary>
    public const uint ClassCode = 0x04;

    /// <summary>Attribute ID for the assembly data attribute.</summary>
    public const ushort DataAttributeId = 3;

    private readonly CipClass _cipClass;
    private readonly Dictionary<uint, AssemblyInstance> _assemblies = new();

    /// <summary>The CIP class object for registration in the dispatcher.</summary>
    public CipClass CipClass => _cipClass;

    /// <summary>Create the Assembly CIP class with standard instance services.</summary>
    public AssemblyObject()
    {
        _cipClass = new CipClass(ClassCode, "Assembly", revision: 2);
        _cipClass.AddStandardInstanceServices();
    }

    /// <summary>
    /// Create an assembly instance with a fixed-size data buffer.
    /// Registers the corresponding CIP instance with attributes 1-4 and links
    /// it to the AssemblyInstance via UserData.
    /// </summary>
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

        // Attribute 3: Data — backed by the AssemblyInstance buffer
        inst.AddAttribute(new AssemblyDataAttribute(assembly));

        // Attribute 4: Size (UINT)
        inst.AddAttribute(CipAttribute.Create(4, CipDataType.Uint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, (ushort)dataSize));

        inst.UserData = assembly;

        return assembly;
    }

    /// <summary>Look up an assembly instance by ID. Returns null if not found.</summary>
    public AssemblyInstance? GetAssembly(uint instanceId) =>
        _assemblies.TryGetValue(instanceId, out var asm) ? asm : null;

    /// <summary>All assembly instances keyed by instance ID.</summary>
    public IReadOnlyDictionary<uint, AssemblyInstance> Assemblies => _assemblies;
}

/// <summary>
/// An assembly instance holding a byte array buffer for I/O data.
/// Supports typed read/write and fires DataChanged on any modification.
/// Thread-safe for concurrent reads; writes are serialized via lock.
/// </summary>
public sealed class AssemblyInstance
{
    private readonly byte[] _data;
    private readonly object _writeLock = new();

    /// <summary>The assembly instance ID.</summary>
    public uint InstanceId { get; }

    /// <summary>Size of the data buffer in bytes.</summary>
    public int DataSize { get; }

    /// <summary>Human-readable name for this assembly.</summary>
    public string? Name { get; }

    /// <summary>
    /// Fires after any write to this assembly's data buffer.
    /// Parameters: instance ID, snapshot of the data at the time of the write.
    /// WARNING: May fire on any thread (including the UDP receive thread).
    /// </summary>
    public event Action<uint, ReadOnlyMemory<byte>>? DataChanged;

    /// <summary>Create an assembly instance with a zeroed data buffer of the given size.</summary>
    public AssemblyInstance(uint instanceId, int dataSize, string? name = null)
    {
        InstanceId = instanceId;
        DataSize = dataSize;
        Name = name;
        _data = new byte[dataSize];
    }

    /// <summary>Read the current assembly data. Safe for concurrent reads.</summary>
    public ReadOnlySpan<byte> GetData() => _data;

    /// <summary>Read a slice of the assembly data.</summary>
    public ReadOnlySpan<byte> GetData(int offset, int length) => _data.AsSpan(offset, length);

    /// <summary>Copy current data into a caller-owned buffer.</summary>
    public void CopyDataTo(Span<byte> destination) => _data.AsSpan().CopyTo(destination);

    /// <summary>Get the underlying buffer for direct use by CIP attribute (no copy).</summary>
    internal byte[] GetRawBuffer() => _data;

    /// <summary>Write new data into the assembly buffer. Fires DataChanged.</summary>
    public void SetData(ReadOnlySpan<byte> source)
    {
        lock (_writeLock)
        {
            source.Slice(0, Math.Min(source.Length, _data.Length)).CopyTo(_data);
        }
        FireDataChanged();
    }

    /// <summary>Write a typed value at a byte offset. Fires DataChanged.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Write<T>(int byteOffset, T value) where T : unmanaged
    {
        lock (_writeLock)
        {
            Unsafe.WriteUnaligned(ref _data[byteOffset], value);
        }
        FireDataChanged();
    }

    /// <summary>Read a typed value at a byte offset. No allocation.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public T Read<T>(int byteOffset = 0) where T : unmanaged
    {
        return Unsafe.ReadUnaligned<T>(ref _data[byteOffset]);
    }

    /// <summary>Fire DataChanged with a snapshot of the current data.</summary>
    private void FireDataChanged()
    {
        var handler = DataChanged;
        if (handler != null)
        {
            // Snapshot — subscribers get a copy, not a live reference to the mutable buffer
            var snapshot = _data.AsMemory();
            handler.Invoke(InstanceId, snapshot);
        }
    }
}

/// <summary>
/// Custom CipAttribute backed directly by the AssemblyInstance's raw buffer.
/// Reads and writes to this attribute operate on the live I/O data.
/// </summary>
internal sealed class AssemblyDataAttribute : CipAttribute
{
    public AssemblyDataAttribute(AssemblyInstance assembly)
        : base(AssemblyObject.DataAttributeId, CipDataType.Byte,
               AttributeAccess.GetSingle | AttributeAccess.SetSingle | AttributeAccess.GetAll,
               assembly.GetRawBuffer())
    {
    }
}
