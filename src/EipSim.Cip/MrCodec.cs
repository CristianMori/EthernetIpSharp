using System.Buffers.Binary;

namespace EipSim.Cip;

/// <summary>
/// Pure codec for CIP Message Router request/response wire format.
///
/// Request format:  service_code(1) + path_size_words(1) + path(N) + data
/// Response format: reply_service(1) + reserved(1) + general_status(1) + add_status_size(1) + add_status(N) + data
/// </summary>
public static class MrCodec
{
    /// <summary>
    /// Parse an MR request into its components: service code, parsed path, and request data.
    /// Returns false if the data is too short to contain a valid request.
    /// </summary>
    public static bool TryParseRequest(ReadOnlyMemory<byte> mrData,
        out byte serviceCode, out CipPath path, out ReadOnlyMemory<byte> data)
    {
        var span = mrData.Span;
        if (span.Length < 2)
        {
            serviceCode = 0;
            path = default;
            data = ReadOnlyMemory<byte>.Empty;
            return false;
        }

        serviceCode = span[0];
        byte pathSizeWords = span[1];
        int pathSizeBytes = pathSizeWords * 2;

        if (span.Length < 2 + pathSizeBytes)
        {
            path = default;
            data = ReadOnlyMemory<byte>.Empty;
            return false;
        }

        (path, _) = CipPath.Parse(span.Slice(2, pathSizeBytes));

        data = mrData.Length > 2 + pathSizeBytes
            ? mrData.Slice(2 + pathSizeBytes)
            : ReadOnlyMemory<byte>.Empty;

        return true;
    }

    /// <summary>
    /// Parse an MR request. Convenience wrapper that returns a tuple.
    /// Returns zeroed values if the data is invalid — prefer TryParseRequest for explicit error handling.
    /// </summary>
    public static (byte ServiceCode, CipPath Path, ReadOnlyMemory<byte> Data) ParseRequest(ReadOnlyMemory<byte> mrData)
    {
        if (TryParseRequest(mrData, out var svc, out var path, out var data))
            return (svc, path, data);
        return (0, default, ReadOnlyMemory<byte>.Empty);
    }

    /// <summary>
    /// Parse an MR response into its components.
    /// Response wire format: reply_service(1) + reserved(1) + general_status(1) + add_status_size(1) + add_status(N*2) + data
    /// </summary>
    public static bool TryParseResponse(ReadOnlyMemory<byte> mrData,
        out byte replyService, out CipStatus status, out ReadOnlyMemory<byte> data)
    {
        var span = mrData.Span;
        if (span.Length < 4)
        {
            replyService = 0;
            status = default;
            data = ReadOnlyMemory<byte>.Empty;
            return false;
        }

        replyService = span[0];
        // span[1] is reserved
        byte generalStatus = span[2];
        byte addStatusSize = span[3];

        int addStatusBytes = addStatusSize * 2;
        if (span.Length < 4 + addStatusBytes)
        {
            status = default;
            data = ReadOnlyMemory<byte>.Empty;
            return false;
        }

        var addStatus = new ushort[addStatusSize];
        for (int i = 0; i < addStatusSize; i++)
            addStatus[i] = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(4 + i * 2));

        status = new CipStatus { GeneralStatus = generalStatus, AdditionalStatus = addStatus };

        int dataOffset = 4 + addStatusBytes;
        data = mrData.Length > dataOffset
            ? mrData.Slice(dataOffset)
            : ReadOnlyMemory<byte>.Empty;

        return true;
    }

    /// <summary>
    /// Encode an MR request into wire format.
    /// Returns the number of bytes written.
    /// Throws ArgumentException if the destination buffer is too small.
    /// </summary>
    public static int EncodeRequest(Span<byte> dst, byte serviceCode, ReadOnlySpan<byte> pathBytes, ReadOnlySpan<byte> data)
    {
        int required = 2 + pathBytes.Length + data.Length;
        if (dst.Length < required)
            throw new ArgumentException(
                $"MR request encode requires {required} bytes, buffer has {dst.Length}");

        int offset = 0;
        dst[offset++] = serviceCode;
        dst[offset++] = (byte)(pathBytes.Length / 2); // path size in words
        pathBytes.CopyTo(dst.Slice(offset));
        offset += pathBytes.Length;
        data.CopyTo(dst.Slice(offset));
        offset += data.Length;
        return offset;
    }
}
