using System.Runtime.CompilerServices;
using System.Threading;

namespace EthernetIPSharp.Logix;

/// <summary>
/// Represents a single Logix controller tag with a data buffer and change notifications.
/// Each tag corresponds to one instance of the Symbol Object (class 0x6B).
///
/// <para><b>Concurrency model.</b>  This mirrors real Logix 1756/1769 semantics:
/// tag memory is a plain byte buffer with no snapshot boundary.  Scalar reads and
/// writes on naturally aligned offsets (DINT at %4, REAL at %4, LINT at %8) are
/// atomic on x86/x64.  Multi-scalar and struct reads MAY tear if a scan-side writer
/// races with a CIP-side reader; that is how a 1756 behaves too, and clients that
/// need coherent multi-member reads coordinate via an application-level flag rather
/// than expecting the controller to snapshot.  Do NOT wrap the read/write path in
/// a lock — the scan-side transpiler-generated code writes 10⁵–10⁶ times per scan
/// and cannot afford it.  The one place synchronization IS worthwhile is BOOL bit
/// RMW on a host byte shared by multiple BOOL members; use <see cref="AtomicSetBit"/>
/// for those writes to prevent two writers to different bits from stomping each
/// other.</para>
/// </summary>
public sealed class Tag
{
    private readonly byte[] _data;

    /// <summary>Symbol Object instance ID.</summary>
    public uint InstanceId { get; }

    /// <summary>Tag name as it appears in the controller (e.g. "rate", "MyStruct").</summary>
    public string Name { get; }

    /// <summary>
    /// Symbol Type attribute (attr 2 of Symbol Object).
    /// Bit 15: 1=struct, 0=atomic. Bits 14-13: array dimensions. Bit 12: system tag.
    /// Bits 0-11: CIP data type code (atomic) or template instance ID (struct).
    /// </summary>
    public ushort SymbolType { get; }

    /// <summary>
    /// Tag type parameter used in Read/Write Tag services.
    /// Atomic: CIP type code (0xC2=SINT, 0xC4=DINT, etc.)
    /// Struct: structure handle from Template attr 1.
    /// </summary>
    public ushort TagType { get; }

    /// <summary>Number of elements (1 for scalars, N for arrays; product of <see cref="Dims"/> for multi-dim).</summary>
    public int ElementCount { get; }

    /// <summary>Bytes per element.</summary>
    public int ElementSize { get; }

    /// <summary>Total data size in bytes.</summary>
    public int DataSize => _data.Length;

    /// <summary>
    /// Array dimension sizes (empty for scalars, one entry for a 1-D array, up to
    /// three entries for a Logix multi-dimensional array like <c>DINT[5,10,2]</c>).
    /// Symbol Object attribute 8 emits these three UDINTs (0-padded).
    /// </summary>
    public IReadOnlyList<uint> Dims { get; }

    /// <summary>
    /// Fires after any write to this tag's data.
    /// Callback receives the tag and info about what changed.
    /// WARNING: May fire on any thread (including the TCP handler thread).
    /// </summary>
    public event Action<Tag, TagChangeInfo>? ValueChanged;

    public Tag(uint instanceId, string name, ushort symbolType, ushort tagType,
               int elementSize, int elementCount = 1)
        : this(instanceId, name, symbolType, tagType, elementSize,
               elementCount > 1 ? new uint[] { (uint)elementCount } : Array.Empty<uint>())
    {
    }

    /// <summary>Construct a tag with an explicit multi-dimensional array shape.</summary>
    public Tag(uint instanceId, string name, ushort symbolType, ushort tagType,
               int elementSize, uint[] dims)
    {
        InstanceId = instanceId;
        Name = name;
        SymbolType = symbolType;
        TagType = tagType;
        ElementSize = elementSize;
        Dims = dims;

        long total = 1;
        for (int i = 0; i < dims.Length; i++) total *= dims[i];
        ElementCount = dims.Length == 0 ? 1 : (int)total;
        _data = new byte[elementSize * ElementCount];
    }

    /// <summary>Read the entire tag data buffer.</summary>
    public ReadOnlySpan<byte> GetData() => _data;

    /// <summary>Read a slice of the tag data starting at a byte offset.</summary>
    public ReadOnlySpan<byte> GetData(int byteOffset, int length) =>
        _data.AsSpan(byteOffset, length);

    /// <summary>Read a typed value at a byte offset. No allocation.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public T Read<T>(int byteOffset = 0) where T : unmanaged =>
        Unsafe.ReadUnaligned<T>(ref _data[byteOffset]);

    /// <summary>Write a typed value at a byte offset. Fires ValueChanged.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Write<T>(int byteOffset, T value) where T : unmanaged
    {
        Unsafe.WriteUnaligned(ref _data[byteOffset], value);
        ValueChanged?.Invoke(this, new TagChangeInfo(byteOffset, Unsafe.SizeOf<T>()));
    }

    /// <summary>Bulk write into the tag data buffer. Fires ValueChanged once.</summary>
    public void SetData(ReadOnlySpan<byte> source, int byteOffset = 0)
    {
        int len = Math.Min(source.Length, _data.Length - byteOffset);
        source.Slice(0, len).CopyTo(_data.AsSpan(byteOffset));
        ValueChanged?.Invoke(this, new TagChangeInfo(byteOffset, len));
    }

    /// <summary>
    /// Atomically set or clear a single bit inside the tag's data buffer.  Used for
    /// BOOL member writes where multiple BOOLs share a host byte — a non-atomic
    /// read/modify/write would allow two concurrent writers to different bits to
    /// stomp each other.
    ///
    /// The implementation reinterprets the containing 4-byte aligned word as a
    /// <c>ref uint</c> and calls <see cref="Interlocked.Or(ref uint, uint)"/> /
    /// <see cref="Interlocked.And(ref uint, uint)"/>.  ValueChanged fires with the
    /// single-byte range of the host byte.
    /// </summary>
    public void AtomicSetBit(int byteOffset, int bitPos, bool value)
    {
        if ((uint)bitPos > 7) throw new ArgumentOutOfRangeException(nameof(bitPos));
        if ((uint)byteOffset >= (uint)_data.Length) throw new ArgumentOutOfRangeException(nameof(byteOffset));

        // Find the 4-byte aligned word containing this byte and compute the bit's
        // position inside that word (little-endian byte order).
        int wordOffset = byteOffset & ~3;
        int bitInWord = ((byteOffset - wordOffset) * 8) + bitPos;
        uint mask = 1u << bitInWord;

        // If the tag's buffer is too short to hold the aligned word, fall back to
        // a plain (non-atomic) RMW.  Tags this small can't have BOOL packing
        // ambiguity anyway.
        if (wordOffset + 4 > _data.Length)
        {
            byte host = _data[byteOffset];
            byte b = (byte)(1 << bitPos);
            _data[byteOffset] = value ? (byte)(host | b) : (byte)(host & ~b);
        }
        else
        {
            ref uint word = ref Unsafe.As<byte, uint>(ref _data[wordOffset]);
            if (value) Interlocked.Or(ref word, mask);
            else Interlocked.And(ref word, ~mask);
        }

        ValueChanged?.Invoke(this, new TagChangeInfo(byteOffset, 1));
    }

    public override string ToString() => $"{Name} ({ElementCount}x{ElementSize}B, type=0x{TagType:X4})";
}

/// <summary>Describes which region of a tag's data was modified.</summary>
public readonly struct TagChangeInfo
{
    /// <summary>Byte offset where the change starts.</summary>
    public int ByteOffset { get; }

    /// <summary>Number of bytes changed.</summary>
    public int ByteLength { get; }

    public TagChangeInfo(int byteOffset, int byteLength)
    {
        ByteOffset = byteOffset;
        ByteLength = byteLength;
    }
}
