using System.Buffers.Binary;
using System.Text;

namespace EthernetIPSharp.Cip;

/// <summary>
/// A single segment inside a CIP EPATH — ordered as it appeared on the wire so that
/// callers can distinguish, for example, <c>Program:Cell.Timer1</c> (two symbolic
/// segments in sequence) from a flattened <c>"Program:Cell.Timer1"</c> string, or the
/// two element indices of <c>Matrix[1,2]</c>.
/// </summary>
public abstract record CipPathSegment;

/// <summary>ANSI Extended Symbolic Segment (0x91) — a single member/scope name.</summary>
public sealed record SymbolicPathSegment(string Name) : CipPathSegment;

/// <summary>Logical Element ID segment (0x28/0x29/0x2A) — one index into a tag array.</summary>
public sealed record ElementPathSegment(uint Index) : CipPathSegment;

/// <summary>
/// Logical segment other than Element ID (Class, Instance, Attribute, ConnectionPoint).
/// The convenience fields on <see cref="CipPath"/> still hold last-seen values so existing
/// callers keep working, but this segment record preserves the on-wire order.
/// </summary>
public sealed record LogicalPathSegment(LogicalSegmentKind Kind, uint Value) : CipPathSegment;

public enum LogicalSegmentKind : byte
{
    ClassId = 0x00,
    InstanceId = 0x04,
    ConnectionPoint = 0x0C,
    AttributeId = 0x10,
}

/// <summary>
/// Parsed CIP EPATH — logical segments (class, instance, attribute, connection point, element),
/// symbolic segments (ANSI Extended Symbolic), and raw path bytes.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Segments"/> holds every parsed segment in the order it appeared on the wire.
/// Use it when segment ordering matters (member drilling after an element index, program-scope
/// prefixes, multi-dimensional array indices).
/// </para>
/// <para>
/// The flat convenience fields (<see cref="ClassId"/>, <see cref="InstanceId"/>,
/// <see cref="AttributeId"/>, <see cref="ConnectionPoint"/>, <see cref="ElementId"/>,
/// <see cref="SymbolicName"/>) are derived from <see cref="Segments"/> for back-compat:
/// scalar logical values keep the last-seen segment's value, and <see cref="SymbolicName"/>
/// is every symbolic segment joined with '.'.  New code should read <see cref="Segments"/>
/// directly instead of these fields when parsing paths that carry members, elements, or
/// program scopes.
/// </para>
/// </remarks>
public readonly struct CipPath
{
    public uint? ClassId { get; init; }
    public uint? InstanceId { get; init; }
    public ushort? AttributeId { get; init; }
    public ushort? ConnectionPoint { get; init; }
    public uint? ElementId { get; init; }

    /// <summary>Full symbolic path from ANSI Extended Symbolic Segments (e.g. "MyStruct.member").</summary>
    public string? SymbolicName { get; init; }

    private readonly IReadOnlyList<CipPathSegment>? _segments;

    /// <summary>Every parsed segment in on-wire order. Empty (never null) when nothing parsed or when the path was built via object-initializer without setting this field.</summary>
    public IReadOnlyList<CipPathSegment> Segments
    {
        get => _segments ?? Array.Empty<CipPathSegment>();
        init => _segments = value;
    }

    /// <summary>Raw EPATH bytes for pass-through or re-parsing.</summary>
    public ReadOnlyMemory<byte>? RawPath { get; init; }

    // Segment type constants
    private const byte SegmentTypeMask = 0xE0;
    private const byte LogicalSegment = 0x20;
    private const byte SymbolicSegmentByte = 0x91; // ANSI Extended Symbolic

    // Logical segment type (bits 4-2)
    private const byte LogicalTypeMask = 0x1C;
    private const byte LogicalTypeClassId = 0x00;
    private const byte LogicalTypeInstanceId = 0x04;
    private const byte LogicalTypeElementId = 0x08;
    private const byte LogicalTypeConnectionPoint = 0x0C;
    private const byte LogicalTypeAttributeId = 0x10;

    // Logical segment format (bits 1-0)
    private const byte LogicalFormatMask = 0x03;
    private const byte LogicalFormat8Bit = 0x00;
    private const byte LogicalFormat16Bit = 0x01;
    private const byte LogicalFormat32Bit = 0x02;

    /// <summary>
    /// Parse an EPATH from a byte span. Returns the path and number of bytes consumed.
    /// Throws <see cref="ArgumentException"/> on a truncated path.
    /// </summary>
    /// <remarks>
    /// Prefer <see cref="TryParse(ReadOnlySpan{byte}, out CipPath, out int)"/> on the
    /// request path — a header like <c>{pathSize=1, body=[0x91, 0xFF]}</c> declares a
    /// 255-char symbolic segment inside 0 remaining bytes, which used to raise
    /// <see cref="ArgumentOutOfRangeException"/> out of here. That exception unwound
    /// through Dispatch into TcpSocketConnection.ReadLoop and was swallowed with no
    /// CIP reply, stalling the client.
    /// </remarks>
    public static (CipPath Path, int BytesConsumed) Parse(ReadOnlySpan<byte> data)
    {
        if (!TryParse(data, out var path, out int consumed))
            throw new ArgumentException("Truncated CIP EPATH");
        return (path, consumed);
    }

    /// <summary>
    /// Non-throwing variant used by the dispatcher. Bounds-checks every segment
    /// advance against <paramref name="data"/>; returns <c>false</c> when a
    /// declared length (symbolic char count, logical format width) runs past
    /// the end of the buffer. The caller is expected to reply with CIP 0x04
    /// Path Segment Error in that case.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out CipPath path, out int bytesConsumed)
    {
        uint? classId = null;
        uint? instanceId = null;
        ushort? attributeId = null;
        ushort? connectionPoint = null;
        uint? elementId = null;
        StringBuilder? symbolicName = null;
        var segments = new List<CipPathSegment>();
        int offset = 0;

        while (offset < data.Length)
        {
            byte segByte = data[offset];

            // ANSI Extended Symbolic Segment (0x91)
            if (segByte == SymbolicSegmentByte)
            {
                // Need: segByte(1) + charCount(1) + name(charCount) + optional pad(1)
                if (offset + 2 > data.Length) { path = default; bytesConsumed = 0; return false; }
                byte charCount = data[offset + 1];
                int nameStart = offset + 2;
                int nameEnd = nameStart + charCount;
                if (nameEnd > data.Length) { path = default; bytesConsumed = 0; return false; }
                int padEnd = (charCount % 2 != 0) ? nameEnd + 1 : nameEnd;
                if (padEnd > data.Length) { path = default; bytesConsumed = 0; return false; }

                var name = Encoding.ASCII.GetString(data.Slice(nameStart, charCount));
                offset = padEnd;

                if (symbolicName == null)
                    symbolicName = new StringBuilder(name);
                else
                    symbolicName.Append('.').Append(name);

                segments.Add(new SymbolicPathSegment(name));

                continue;
            }

            byte segType = (byte)(segByte & SegmentTypeMask);

            if (segType == LogicalSegment)
            {
                byte logicalType = (byte)(segByte & LogicalTypeMask);
                byte format = (byte)(segByte & LogicalFormatMask);
                int cursor = offset + 1;

                uint value;
                switch (format)
                {
                    case LogicalFormat8Bit:
                        if (cursor + 1 > data.Length) { path = default; bytesConsumed = 0; return false; }
                        value = data[cursor];
                        cursor += 1;
                        break;
                    case LogicalFormat16Bit:
                        if (cursor % 2 != 0) cursor++;
                        if (cursor + 2 > data.Length) { path = default; bytesConsumed = 0; return false; }
                        value = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(cursor));
                        cursor += 2;
                        break;
                    case LogicalFormat32Bit:
                        if (cursor % 2 != 0) cursor++;
                        if (cursor + 4 > data.Length) { path = default; bytesConsumed = 0; return false; }
                        value = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(cursor));
                        cursor += 4;
                        break;
                    default:
                        goto done;
                }

                offset = cursor;

                switch (logicalType)
                {
                    case LogicalTypeClassId:
                        classId = value;
                        segments.Add(new LogicalPathSegment(LogicalSegmentKind.ClassId, value));
                        break;
                    case LogicalTypeInstanceId:
                        instanceId = value;
                        segments.Add(new LogicalPathSegment(LogicalSegmentKind.InstanceId, value));
                        break;
                    case LogicalTypeAttributeId:
                        attributeId = (ushort)value;
                        segments.Add(new LogicalPathSegment(LogicalSegmentKind.AttributeId, value));
                        break;
                    case LogicalTypeConnectionPoint:
                        connectionPoint = (ushort)value;
                        segments.Add(new LogicalPathSegment(LogicalSegmentKind.ConnectionPoint, value));
                        break;
                    case LogicalTypeElementId:
                        elementId = value;
                        segments.Add(new ElementPathSegment(value));
                        break;
                }
            }
            else
            {
                break; // Unknown/unhandled segment type — stop
            }
        }

        done:
        path = new CipPath
        {
            ClassId = classId,
            InstanceId = instanceId,
            AttributeId = attributeId,
            ConnectionPoint = connectionPoint,
            ElementId = elementId,
            SymbolicName = symbolicName?.ToString(),
            Segments = segments,
            RawPath = data.Slice(0, offset).ToArray(),
        };
        bytesConsumed = offset;
        return true;
    }

    /// <summary>Encode an 8-bit logical segment.</summary>
    public static int EncodeLogical8(Span<byte> dst, byte logicalType, byte value)
    {
        dst[0] = (byte)(LogicalSegment | logicalType | LogicalFormat8Bit);
        dst[1] = value;
        return 2;
    }

    public override string ToString()
    {
        var parts = new List<string>();
        if (SymbolicName != null) parts.Add($"Sym=\"{SymbolicName}\"");
        if (ClassId.HasValue) parts.Add($"Class=0x{ClassId.Value:X2}");
        if (InstanceId.HasValue) parts.Add($"Instance={InstanceId.Value}");
        if (AttributeId.HasValue) parts.Add($"Attr={AttributeId.Value}");
        if (ConnectionPoint.HasValue) parts.Add($"ConnPt={ConnectionPoint.Value}");
        if (ElementId.HasValue) parts.Add($"Elem={ElementId.Value}");
        return string.Join(", ", parts);
    }
}
