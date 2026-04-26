namespace EipSim.Cip;

/// <summary>
/// Pure codec for CIP Message Router request/response format.
/// Request: service_code(1) + path_size_words(1) + path(N) + data
/// Response: reply_service(1) + reserved(1) + general_status(1) + add_status_size(1) + add_status(N) + data
/// </summary>
public static class MrCodec
{
    /// <summary>
    /// Parse an MR request into its components: service code, parsed path, and request data.
    /// </summary>
    public static (byte ServiceCode, CipPath Path, ReadOnlyMemory<byte> Data) ParseRequest(ReadOnlyMemory<byte> mrData)
    {
        var span = mrData.Span;
        if (span.Length < 2)
            return (0, default, ReadOnlyMemory<byte>.Empty);

        byte serviceCode = span[0];
        byte pathSizeWords = span[1];
        int pathSizeBytes = pathSizeWords * 2;

        if (span.Length < 2 + pathSizeBytes)
            return (serviceCode, default, ReadOnlyMemory<byte>.Empty);

        var (path, _) = CipPath.Parse(span.Slice(2, pathSizeBytes));

        var data = mrData.Length > 2 + pathSizeBytes
            ? mrData.Slice(2 + pathSizeBytes)
            : ReadOnlyMemory<byte>.Empty;

        return (serviceCode, path, data);
    }

    /// <summary>
    /// Encode an MR request into wire format.
    /// </summary>
    public static int EncodeRequest(Span<byte> dst, byte serviceCode, ReadOnlySpan<byte> pathBytes, ReadOnlySpan<byte> data)
    {
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
