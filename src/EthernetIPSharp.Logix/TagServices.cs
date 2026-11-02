using System.Buffers;
using System.Buffers.Binary;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Logix;

/// <summary>
/// CIP service handlers for Logix tag operations:
/// Read Tag (0x4C), Write Tag (0x4D), Read Tag Fragmented (0x52),
/// Write Tag Fragmented (0x53), Read Modify Write (0x4E).
/// Uses ArrayPool to reduce GC pressure on hot read/write paths.
/// </summary>
public static class TagServices
{
    public const byte ReadTag = 0x4C;
    public const byte WriteTag = 0x4D;
    public const byte ReadModifyWrite = 0x4E;
    public const byte ReadTagFragmented = 0x52;
    public const byte WriteTagFragmented = 0x53;

    private const int MaxReplyData = 480; // ~500 bytes minus overhead

    // Structure tag marker on the wire. CIP Vol 1 §C-4.4.5: a Read_Tag reply
    // for a structured tag leads with [A0 02][structure_handle (UINT)] followed
    // by the raw structure bytes; a Write_Tag request uses the same prefix
    // ahead of element_count and the data. Atomic tags carry only the 2-byte
    // type code. libplctag and pycomm3 both enforce this split.
    private const ushort StructTypeIndicator = 0x02A0;

    private static bool IsStructTag(Tag tag) => LogixDataTypes.IsStruct(tag.SymbolType);

    /// <summary>
    /// Read Tag Service (0x4C).
    /// Request: element_count (UINT)
    /// Reply: tag_type (UINT) + data bytes
    /// elementOffset indexes into the tag's array (0 for scalars or
    /// whole-tag reads); byte offset = elementOffset * tag.ElementSize.
    /// </summary>
    public static CipServiceResponse HandleReadTag(Tag tag, byte serviceCode, ReadOnlyMemory<byte> data,
        int elementOffset = 0)
    {
        if (data.Length < 2)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        ushort elementCount = BinaryPrimitives.ReadUInt16LittleEndian(data.Span);
        int byteOffset = elementOffset * tag.ElementSize;
        int bytesToRead = elementCount * tag.ElementSize;

        if (byteOffset + bytesToRead > tag.DataSize)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        int prefixLen = IsStructTag(tag) ? 4 : 2;
        int responseLen = prefixLen + bytesToRead;

        // Check if data fits in reply
        if (responseLen > MaxReplyData)
        {
            int fitBytes = MaxReplyData - prefixLen;
            return BuildReadResponse(tag, serviceCode, byteOffset, fitBytes, isPartial: true);
        }

        return BuildReadResponse(tag, serviceCode, byteOffset, bytesToRead, isPartial: false);
    }

    /// <summary>
    /// Write Tag Service (0x4D).
    /// Request: tag_type (UINT) + element_count (UINT) + data bytes
    /// Reply: (empty on success)
    /// </summary>
    public static CipServiceResponse HandleWriteTag(Tag tag, byte serviceCode, ReadOnlyMemory<byte> data,
        int elementOffset = 0)
    {
        if (data.Length < 4)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var span = data.Span;
        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(span);

        ushort elementCount;
        int headerLen;

        if (IsStructTag(tag))
        {
            if (data.Length < 6)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

            ushort structHandle = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));
            elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(4));
            headerLen = 6;

            if (tagType != StructTypeIndicator || structHandle != tag.TagType)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));
        }
        else
        {
            elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));
            headerLen = 4;

            if (tagType != tag.TagType)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));
        }

        int byteOffset = elementOffset * tag.ElementSize;
        int bytesToWrite = elementCount * tag.ElementSize;
        if (data.Length < headerLen + bytesToWrite)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        if (byteOffset + bytesToWrite > tag.DataSize)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        tag.SetData(span.Slice(headerLen, bytesToWrite), byteOffset);

        return CipServiceResponse.Success(serviceCode);
    }

    /// <summary>
    /// Read Tag Fragmented Service (0x52).
    /// Request: element_count (UINT) + byte_offset (UDINT)
    /// Reply: tag_type (UINT) + data bytes (status 0x06 if more data remains)
    /// </summary>
    public static CipServiceResponse HandleReadTagFragmented(Tag tag, byte serviceCode, ReadOnlyMemory<byte> data)
    {
        if (data.Length < 6)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var span = data.Span;
        ushort elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span);
        uint byteOffset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(2));

        int totalBytes = elementCount * tag.ElementSize;
        if (byteOffset >= (uint)totalBytes)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        int prefixLen = IsStructTag(tag) ? 4 : 2;
        int remaining = totalBytes - (int)byteOffset;
        int chunkSize = Math.Min(remaining, MaxReplyData - prefixLen);
        bool moreData = (int)byteOffset + chunkSize < totalBytes;

        return BuildReadResponse(tag, serviceCode, (int)byteOffset, chunkSize, isPartial: moreData);
    }

    /// <summary>
    /// Write Tag Fragmented Service (0x53).
    /// Request: tag_type (UINT) + element_count (UINT) + byte_offset (UDINT) + data
    /// Reply: (empty on success)
    /// </summary>
    public static CipServiceResponse HandleWriteTagFragmented(Tag tag, byte serviceCode, ReadOnlyMemory<byte> data)
    {
        if (data.Length < 8)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var span = data.Span;
        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(span);

        ushort elementCount;
        uint byteOffset;
        int headerLen;

        if (IsStructTag(tag))
        {
            // Struct fragmented write: [0x02A0][struct_handle][count][offset][data...]
            if (data.Length < 10)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

            ushort structHandle = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));
            elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(4));
            byteOffset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(6));
            headerLen = 10;

            if (tagType != StructTypeIndicator || structHandle != tag.TagType)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));
        }
        else
        {
            elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));
            byteOffset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(4));
            headerLen = 8;

            if (tagType != tag.TagType)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));
        }

        int totalBytes = elementCount * tag.ElementSize;
        int writeLen = data.Length - headerLen;
        if (byteOffset + (uint)writeLen > (uint)totalBytes)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2104));

        tag.SetData(span.Slice(headerLen, writeLen), (int)byteOffset);

        return CipServiceResponse.Success(serviceCode);
    }

    /// <summary>
    /// Read Modify Write Tag Service (0x4E).
    /// Request: mask_size (UINT) + OR_masks + AND_masks
    /// Reply: (empty on success)
    /// </summary>
    public static CipServiceResponse HandleReadModifyWrite(Tag tag, byte serviceCode, ReadOnlyMemory<byte> data)
    {
        if (data.Length < 2)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var span = data.Span;
        ushort maskSize = BinaryPrimitives.ReadUInt16LittleEndian(span);

        if (maskSize != 1 && maskSize != 2 && maskSize != 4 && maskSize != 8 && maskSize != 12)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x03));

        if (data.Length < 2 + maskSize * 2)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var orMask = span.Slice(2, maskSize);
        var andMask = span.Slice(2 + maskSize, maskSize);

        // Apply: data = (data OR orMask) AND andMask
        int len = Math.Min(maskSize, tag.DataSize);
        var rented = ArrayPool<byte>.Shared.Rent(len);
        try
        {
            tag.GetData(0, len).CopyTo(rented);
            for (int i = 0; i < len; i++)
                rented[i] = (byte)((rented[i] | orMask[i]) & andMask[i]);
            tag.SetData(rented.AsSpan(0, len));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }

        return CipServiceResponse.Success(serviceCode);
    }

    /// <summary>
    /// Shared helper to build a Read Tag / Read Tag Fragmented response.
    /// Whole-tag path: emits [0x02A0][struct_handle][data] for structured tags
    /// and [type_code][data] for atomic. Uses ArrayPool to avoid per-call
    /// allocations on the hot read path.
    /// </summary>
    private static CipServiceResponse BuildReadResponse(Tag tag, byte serviceCode,
        int byteOffset, int dataLength, bool isPartial)
    {
        if (IsStructTag(tag))
            return BuildStructReadResponse(tag, serviceCode, byteOffset, dataLength, isPartial, tag.TagType);
        return BuildAtomicReadResponse(tag, serviceCode, byteOffset, dataLength, isPartial, tag.TagType);
    }

    /// <summary>
    /// Walker-aware variant. The caller resolves the struct-vs-atomic decision
    /// (from <c>walked.Template != null</c>) and passes the correct type code —
    /// for atomics the CIP type code, for structs the structure handle (used
    /// after the 0x02A0 indicator on the wire).
    /// </summary>
    private static CipServiceResponse BuildReadResponseAtomicOrStruct(Tag tag, byte serviceCode,
        int byteOffset, int dataLength, bool isPartial, ushort typeOrHandle, bool asStruct)
    {
        return asStruct
            ? BuildStructReadResponse(tag, serviceCode, byteOffset, dataLength, isPartial, typeOrHandle)
            : BuildAtomicReadResponse(tag, serviceCode, byteOffset, dataLength, isPartial, typeOrHandle);
    }

    private static CipServiceResponse BuildAtomicReadResponse(Tag tag, byte serviceCode,
        int byteOffset, int dataLength, bool isPartial, ushort typeCode)
    {
        int responseLen = 2 + dataLength;
        var rented = ArrayPool<byte>.Shared.Rent(responseLen);
        try
        {
            BinaryPrimitives.WriteUInt16LittleEndian(rented, typeCode);
            tag.GetData(byteOffset, dataLength).CopyTo(rented.AsSpan(2));
            return FinalizeReadResponse(serviceCode, rented, responseLen, isPartial);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static CipServiceResponse BuildStructReadResponse(Tag tag, byte serviceCode,
        int byteOffset, int dataLength, bool isPartial, ushort structHandle)
    {
        int responseLen = 4 + dataLength;
        var rented = ArrayPool<byte>.Shared.Rent(responseLen);
        try
        {
            BinaryPrimitives.WriteUInt16LittleEndian(rented, StructTypeIndicator);
            BinaryPrimitives.WriteUInt16LittleEndian(rented.AsSpan(2), structHandle);
            tag.GetData(byteOffset, dataLength).CopyTo(rented.AsSpan(4));
            return FinalizeReadResponse(serviceCode, rented, responseLen, isPartial);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static CipServiceResponse FinalizeReadResponse(byte serviceCode, byte[] rented,
        int responseLen, bool isPartial)
    {
        var result = rented.AsSpan(0, responseLen).ToArray();

        if (isPartial)
        {
            return new CipServiceResponse
            {
                ServiceCode = (byte)(serviceCode | 0x80),
                Status = CipStatus.Error(0x06),
                Data = result,
            };
        }

        return CipServiceResponse.Success(serviceCode, result);
    }

    // --- Walker-aware variants ---
    // These accept a pre-resolved TagPathWalker.WalkResult (byte offset, type code,
    // element size, optional BOOL bit position) rather than deriving the offset
    // from `elementOffset * tag.ElementSize` at byte 0. Used by LogixDispatcher
    // whenever a request path carries member or element segments past the root.

    /// <summary>Read Tag at a walker-resolved target (member, element, or BOOL bit).</summary>
    public static CipServiceResponse HandleReadTagAt(Tag tag, byte serviceCode,
        ReadOnlyMemory<byte> data, TagPathWalker.WalkResult walked)
    {
        if (data.Length < 2)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        ushort elementCount = BinaryPrimitives.ReadUInt16LittleEndian(data.Span);

        // BOOL member bit read: single element, one byte of 0x01 / 0x00.
        if (walked.BitPos.HasValue)
        {
            if (elementCount != 1)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

            byte host = tag.GetData(walked.Offset, 1)[0];
            byte bit = (byte)((host >> walked.BitPos.Value) & 0x01);
            var reply = new byte[3];
            BinaryPrimitives.WriteUInt16LittleEndian(reply, LogixDataTypes.BOOL);
            reply[2] = bit;
            return CipServiceResponse.Success(serviceCode, reply);
        }

        int bytesToRead = elementCount * walked.ElementSize;
        if (walked.Offset + bytesToRead > tag.DataSize)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        // A walker that ends on a nested struct member carries a non-null Template
        // and the structure handle is on the Template. Atomic members have a plain
        // CIP type code in walked.TypeCode and no Template.
        bool asStruct = walked.Template is not null;
        ushort typeOrHandle = asStruct ? walked.Template!.StructureHandle : walked.TypeCode;
        int prefixLen = asStruct ? 4 : 2;

        int responseLen = prefixLen + bytesToRead;
        if (responseLen > MaxReplyData)
        {
            int fitBytes = MaxReplyData - prefixLen;
            return BuildReadResponseAtomicOrStruct(tag, serviceCode, walked.Offset, fitBytes, isPartial: true, typeOrHandle, asStruct);
        }
        return BuildReadResponseAtomicOrStruct(tag, serviceCode, walked.Offset, bytesToRead, isPartial: false, typeOrHandle, asStruct);
    }

    /// <summary>Write Tag at a walker-resolved target (member, element, or BOOL bit).</summary>
    public static CipServiceResponse HandleWriteTagAt(Tag tag, byte serviceCode,
        ReadOnlyMemory<byte> data, TagPathWalker.WalkResult walked)
    {
        if (data.Length < 4)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var span = data.Span;
        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(span);

        bool asStruct = walked.Template is not null;
        ushort elementCount;
        int headerLen;

        if (asStruct)
        {
            if (data.Length < 6)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

            ushort structHandle = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));
            elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(4));
            headerLen = 6;

            if (tagType != StructTypeIndicator || structHandle != walked.Template!.StructureHandle)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));
        }
        else
        {
            elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));
            headerLen = 4;

            if (tagType != walked.TypeCode)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));
        }

        // BOOL member bit write: atomic RMW on the host byte via Interlocked so
        // two writers to different bits of the same host byte cannot stomp each
        // other. Cost is a single locked instruction per bit write.
        if (walked.BitPos.HasValue)
        {
            if (elementCount != 1 || data.Length < headerLen + 1)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

            bool newValue = (span[headerLen] & 0x01) != 0;
            tag.AtomicSetBit(walked.Offset, walked.BitPos.Value, newValue);
            return CipServiceResponse.Success(serviceCode);
        }

        int bytesToWrite = elementCount * walked.ElementSize;
        if (data.Length < headerLen + bytesToWrite)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        if (walked.Offset + bytesToWrite > tag.DataSize)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        tag.SetData(span.Slice(headerLen, bytesToWrite), walked.Offset);
        return CipServiceResponse.Success(serviceCode);
    }

    /// <summary>
    /// Read-Modify-Write at a walker-resolved target. For BOOL members we honor the
    /// walker's bit position rather than the client-supplied mask offset (a client
    /// that already resolved the member to a bit will still send a 1-byte mask).
    /// </summary>
    public static CipServiceResponse HandleReadModifyWriteAt(Tag tag, byte serviceCode,
        ReadOnlyMemory<byte> data, TagPathWalker.WalkResult walked)
    {
        if (data.Length < 2)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var span = data.Span;
        ushort maskSize = BinaryPrimitives.ReadUInt16LittleEndian(span);
        if (maskSize != 1 && maskSize != 2 && maskSize != 4 && maskSize != 8 && maskSize != 12)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x03));
        if (data.Length < 2 + maskSize * 2)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var orMask = span.Slice(2, maskSize);
        var andMask = span.Slice(2 + maskSize, maskSize);

        int len = Math.Min(maskSize, tag.DataSize - walked.Offset);
        if (len <= 0)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        var rented = ArrayPool<byte>.Shared.Rent(len);
        try
        {
            tag.GetData(walked.Offset, len).CopyTo(rented);
            for (int i = 0; i < len; i++)
                rented[i] = (byte)((rented[i] | orMask[i]) & andMask[i]);
            tag.SetData(rented.AsSpan(0, len), walked.Offset);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }

        return CipServiceResponse.Success(serviceCode);
    }

    /// <summary>Fragmented Read at a walker-resolved base offset.</summary>
    public static CipServiceResponse HandleReadTagFragmentedAt(Tag tag, byte serviceCode,
        ReadOnlyMemory<byte> data, TagPathWalker.WalkResult walked)
    {
        if (data.Length < 6)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));
        if (walked.BitPos.HasValue)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x08)); // fragmented on a BOOL bit is nonsense

        var span = data.Span;
        ushort elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span);
        uint byteOffsetInMember = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(2));

        int totalBytes = elementCount * walked.ElementSize;
        if (byteOffsetInMember >= (uint)totalBytes)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        bool asStruct = walked.Template is not null;
        ushort typeOrHandle = asStruct ? walked.Template!.StructureHandle : walked.TypeCode;
        int prefixLen = asStruct ? 4 : 2;

        int remaining = totalBytes - (int)byteOffsetInMember;
        int chunkSize = Math.Min(remaining, MaxReplyData - prefixLen);
        bool moreData = (int)byteOffsetInMember + chunkSize < totalBytes;
        int absoluteOffset = walked.Offset + (int)byteOffsetInMember;

        return BuildReadResponseAtomicOrStruct(tag, serviceCode, absoluteOffset, chunkSize, isPartial: moreData, typeOrHandle, asStruct);
    }

    /// <summary>Fragmented Write at a walker-resolved base offset.</summary>
    public static CipServiceResponse HandleWriteTagFragmentedAt(Tag tag, byte serviceCode,
        ReadOnlyMemory<byte> data, TagPathWalker.WalkResult walked)
    {
        if (data.Length < 8)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));
        if (walked.BitPos.HasValue)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x08));

        var span = data.Span;
        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(span);

        bool asStruct = walked.Template is not null;
        ushort elementCount;
        uint byteOffsetInMember;
        int headerLen;

        if (asStruct)
        {
            // Struct fragmented write: [0x02A0][struct_handle][count][offset][data...]
            if (data.Length < 10)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

            ushort structHandle = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));
            elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(4));
            byteOffsetInMember = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(6));
            headerLen = 10;

            if (tagType != StructTypeIndicator || structHandle != walked.Template!.StructureHandle)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));
        }
        else
        {
            elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));
            byteOffsetInMember = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(4));
            headerLen = 8;

            if (tagType != walked.TypeCode)
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));
        }

        int totalBytes = elementCount * walked.ElementSize;
        int writeLen = data.Length - headerLen;
        if (byteOffsetInMember + (uint)writeLen > (uint)totalBytes)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2104));

        tag.SetData(span.Slice(headerLen, writeLen), walked.Offset + (int)byteOffsetInMember);
        return CipServiceResponse.Success(serviceCode);
    }
}
