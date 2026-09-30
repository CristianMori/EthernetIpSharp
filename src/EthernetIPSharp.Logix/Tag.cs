using System.Runtime.CompilerServices;

namespace EthernetIPSharp.Logix;

/// <summary>
/// Represents a single Logix controller tag with a data buffer and change notifications.
/// Each tag corresponds to one instance of the Symbol Object (class 0x6B).
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

    /// <summary>Number of elements (1 for scalars, N for arrays).</summary>
    public int ElementCount { get; }

    /// <summary>Bytes per element.</summary>
    public int ElementSize { get; }

    /// <summary>Total data size in bytes.</summary>
    public int DataSize => _data.Length;

    /// <summary>
    /// Fires after any write to this tag's data.
    /// Callback receives the tag and info about what changed.
    /// WARNING: May fire on any thread (including the TCP handler thread).
    /// </summary>
    public event Action<Tag, TagChangeInfo>? ValueChanged;

    public Tag(uint instanceId, string name, ushort symbolType, ushort tagType,
               int elementSize, int elementCount = 1)
    {
        InstanceId = instanceId;
        Name = name;
        SymbolType = symbolType;
        TagType = tagType;
        ElementSize = elementSize;
        ElementCount = elementCount;
        _data = new byte[elementSize * elementCount];
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

    public override string ToString() => $"{Name} ({ElementCount}x{ElementSize}B, type=0x{TagType:X4})";
    
    public bool IsSString => (TagType & 0x00FF) == LogixDataTypes.SHORT_STRING;

    public string ReadSString()
    {
        if (!IsSString)
        {
            throw new InvalidOperationException(
                $"Tag '{Name}' is not a SHORT_STRING tag."
            );
        }

        if (_data.Length < LogixDataTypes.ShortStringStorageSize)
        {
            throw new InvalidOperationException(
                $"Tag '{Name}' has an invalid SHORT_STRING buffer."
            );
        }

        // Truncate output if somehow string is too big in memory.
        int length = Math.Min((int)_data[0], LogixDataTypes.ShortStringMaxLength);
        return Encoding.ASCII.GetString(_data, 1, length);
    }

    public void WriteSString(string value)
    {
        if (!IsSString)
        {
            throw new InvalidOperationException(
                $"Tag '{Name}' is not a SHORT_STRING tag."
            );
        }

        ArgumentNullException.ThrowIfNull(value);

        if (value.Length > LogixDataTypes.ShortStringMaxLength)
        {
            throw new ArgumentException(
                $"SHORT_STRING supports a maximum of " +
                $"{LogixDataTypes.ShortStringMaxLength} characters.",
                nameof(value)
            );
        }

        // SHORT_STRING is one byte per character.
        if (value.Any(c => c > 0x7F))
        {
            throw new ArgumentException(
                "SHORT_STRING values must contain ASCII characters.",
                nameof(value)
            );
        }

        byte[] characters = Encoding.ASCII.GetBytes(value);

        Array.Clear(_data, 0, _data.Length);

        // Byte 0 is the character count.
        _data[0] = checked((byte)characters.Length);

        // Bytes 1..80 contain the character data.
        characters.CopyTo(_data, 1);

        ValueChanged?.Invoke(this, new TagChangeInfo(0, _data.Length));
    }
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
