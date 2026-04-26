using System.Buffers.Binary;
using EipSim.Cip;

namespace EipSim.Logix;

/// <summary>
/// CIP service handlers for Logix tag operations:
/// Read Tag (0x4C), Write Tag (0x4D), Read Tag Fragmented (0x52),
/// Write Tag Fragmented (0x53), Read Modify Write (0x4E).
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
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13)); // Insufficient data

        ushort elementCount = BinaryPrimitives.ReadUInt16LittleEndian(data.Span);
        int bytesToRead = elementCount * tag.ElementSize;

        if (bytesToRead > tag.DataSize)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105)); // Beyond end

        // Build response: tag_type (2 bytes) + data
        var responseData = new byte[2 + bytesToRead];
        BinaryPrimitives.WriteUInt16LittleEndian(responseData, tag.TagType);
        tag.GetData(0, bytesToRead).CopyTo(responseData.AsSpan(2));

        // Check if data fits in reply
        if (responseData.Length > MaxReplyData)
        {
            // Return what fits with status 0x06 (Insufficient Packet Space)
            int fitBytes = MaxReplyData - 2; // minus tag type
            var partial = new byte[2 + fitBytes];
            BinaryPrimitives.WriteUInt16LittleEndian(partial, tag.TagType);
            tag.GetData(0, fitBytes).CopyTo(partial.AsSpan(2));
            return new CipServiceResponse
            {
                ServiceCode = (byte)(serviceCode | 0x80),
                Status = CipStatus.Error(0x06),
                Data = partial,
            };
        }

        return CipServiceResponse.Success(serviceCode, responseData);
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

        // Validate tag type matches
        if (tagType != tag.TagType)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2107)); // Type mismatch

        int bytesToWrite = elementCount * tag.ElementSize;
        if (data.Length < 4 + bytesToWrite)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        if (bytesToWrite > tag.DataSize)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0xFF, 0x2105));

        // Write data — this fires Tag.ValueChanged
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

        var responseData = new byte[2 + chunkSize];
        BinaryPrimitives.WriteUInt16LittleEndian(responseData, tag.TagType);
        tag.GetData((int)byteOffset, chunkSize).CopyTo(responseData.AsSpan(2));

        bool moreData = (int)byteOffset + chunkSize < totalBytes;

        if (moreData)
        {
            return new CipServiceResponse
            {
                ServiceCode = (byte)(serviceCode | 0x80),
                Status = CipStatus.Error(0x06), // More data
                Data = responseData,
            };
        }

        return CipServiceResponse.Success(serviceCode, responseData);
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

        // maskSize must be 1, 2, 4, 8, or 12
        if (maskSize != 1 && maskSize != 2 && maskSize != 4 && maskSize != 8 && maskSize != 12)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x03)); // Bad parameter

        if (data.Length < 2 + maskSize * 2)
            return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x13));

        var orMask = span.Slice(2, maskSize);
        var andMask = span.Slice(2 + maskSize, maskSize);

        // Apply: data = (data OR orMask) AND andMask
        int len = Math.Min(maskSize, tag.DataSize);
        var modified = new byte[len];
        tag.GetData(0, len).CopyTo(modified);
        for (int i = 0; i < len; i++)
        {
            modified[i] = (byte)((modified[i] | orMask[i]) & andMask[i]);
        }
        tag.SetData(modified);

        return CipServiceResponse.Success(serviceCode);
    }
}
