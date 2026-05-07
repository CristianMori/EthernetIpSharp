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

    /// <summary>
    /// Read Tag Service (0x4C).
    /// Request: element_count (UINT)
    /// Reply: tag_type (UINT) + data bytes
    /// </summary>
    public static CipServiceResponse HandleReadTag(Tag tag, byte serviceCode, ReadOnlyMemory<byte> data)
    {
        if (data.Length < 2)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        ushort elementCount = BinaryPrimitives.ReadUInt16LittleEndian(data.Span);
        int bytesToRead = elementCount * tag.ElementSize;

        if (bytesToRead > tag.DataSize)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        int responseLen = 2 + bytesToRead;

        // Check if data fits in reply
        if (responseLen > MaxReplyData)
        {
            int fitBytes = MaxReplyData - 2;
            return BuildReadResponse(tag, serviceCode, 0, fitBytes, isPartial: true);
        }

        return BuildReadResponse(tag, serviceCode, 0, bytesToRead, isPartial: false);
    }

    /// <summary>
    /// Write Tag Service (0x4D).
    /// Request: tag_type (UINT) + element_count (UINT) + data bytes
    /// Reply: (empty on success)
    /// </summary>
    public static CipServiceResponse HandleWriteTag(Tag tag, byte serviceCode, ReadOnlyMemory<byte> data)
    {
        if (data.Length < 4)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var span = data.Span;
        ushort tagType = BinaryPrimitives.ReadUInt16LittleEndian(span);
        ushort elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));

        if (tagType != tag.TagType)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));

        int bytesToWrite = elementCount * tag.ElementSize;
        if (data.Length < 4 + bytesToWrite)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        if (bytesToWrite > tag.DataSize)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        tag.SetData(span.Slice(4, bytesToWrite));

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

        int remaining = totalBytes - (int)byteOffset;
        int chunkSize = Math.Min(remaining, MaxReplyData - 2);
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
        ushort elementCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2));
        uint byteOffset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(4));

        if (tagType != tag.TagType)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107));

        int totalBytes = elementCount * tag.ElementSize;
        if (byteOffset + (uint)(data.Length - 8) > (uint)totalBytes)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2104));

        int writeLen = data.Length - 8;
        tag.SetData(span.Slice(8, writeLen), (int)byteOffset);

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
    /// Uses ArrayPool to avoid per-call allocations on the hot read path.
    /// </summary>
    private static CipServiceResponse BuildReadResponse(Tag tag, byte serviceCode,
        int byteOffset, int dataLength, bool isPartial)
    {
        int responseLen = 2 + dataLength;
        var rented = ArrayPool<byte>.Shared.Rent(responseLen);
        try
        {
            BinaryPrimitives.WriteUInt16LittleEndian(rented, tag.TagType);
            tag.GetData(byteOffset, dataLength).CopyTo(rented.AsSpan(2));

            // Copy to exact-sized array for the response (ArrayPool may over-allocate)
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
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}
