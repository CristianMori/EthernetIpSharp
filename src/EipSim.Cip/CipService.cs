namespace EipSim.Cip;

public readonly struct CipServiceRequest
{
    public byte ServiceCode { get; init; }
    public CipPath Path { get; init; }
    public ReadOnlyMemory<byte> Data { get; init; }
}

public readonly struct CipServiceResponse
{
    public byte ServiceCode { get; init; }
    public CipStatus Status { get; init; }
    public ReadOnlyMemory<byte> Data { get; init; }

    public static CipServiceResponse Success(byte serviceCode, ReadOnlyMemory<byte> data = default) =>
        new() { ServiceCode = (byte)(serviceCode | 0x80), Status = CipStatus.Success, Data = data };

    public static CipServiceResponse Error(byte serviceCode, CipStatus status) =>
        new() { ServiceCode = (byte)(serviceCode | 0x80), Status = status };

    /// <summary>Encode the MR response format: reply service | reserved | status | additional status size | additional status | data</summary>
    public int Encode(Span<byte> dst)
    {
        int offset = 0;
        dst[offset++] = ServiceCode;
        dst[offset++] = 0; // reserved
        offset += Status.Encode(dst.Slice(offset));
        if (!Data.IsEmpty)
        {
            Data.Span.CopyTo(dst.Slice(offset));
            offset += Data.Length;
        }
        return offset;
    }
}

public delegate CipServiceResponse CipServiceHandler(CipInstance instance, CipServiceRequest request);

public sealed class CipServiceDefinition
{
    public byte ServiceCode { get; }
    public string Name { get; }
    public CipServiceHandler Handler { get; }

    public CipServiceDefinition(byte serviceCode, string name, CipServiceHandler handler)
    {
        ServiceCode = serviceCode;
        Name = name;
        Handler = handler;
    }
}
