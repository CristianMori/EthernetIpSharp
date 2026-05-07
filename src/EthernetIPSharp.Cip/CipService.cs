namespace EthernetIPSharp.Cip;

/// <summary>
/// A CIP service request — service code, target path, and request-specific data.
/// Passed to service handlers by the dispatcher.
/// </summary>
public readonly struct CipServiceRequest
{
    /// <summary>CIP service code (e.g. 0x0E = GetAttributeSingle, 0x4C = Read Tag).</summary>
    public byte ServiceCode { get; init; }

    /// <summary>Parsed EPATH identifying the target class/instance/attribute.</summary>
    public CipPath Path { get; init; }

    /// <summary>Service-specific request data (after the path in the MR request).</summary>
    public ReadOnlyMemory<byte> Data { get; init; }
}

/// <summary>
/// A CIP service response — reply service code (with bit 7 set), status, and response data.
/// Returned by service handlers and encoded to MR response wire format.
/// </summary>
public readonly struct CipServiceResponse
{
    /// <summary>Reply service code (original service code | 0x80).</summary>
    public byte ServiceCode { get; init; }

    /// <summary>CIP status (general status + optional additional status words).</summary>
    public CipStatus Status { get; init; }

    /// <summary>Service-specific response data.</summary>
    public ReadOnlyMemory<byte> Data { get; init; }

    /// <summary>Create a success response with the reply bit set.</summary>
    public static CipServiceResponse Success(byte serviceCode, ReadOnlyMemory<byte> data = default) =>
        new() { ServiceCode = (byte)(serviceCode | 0x80), Status = CipStatus.Success, Data = data };

    /// <summary>Create an error response with the reply bit set.</summary>
    public static CipServiceResponse Error(byte serviceCode, CipStatus status) =>
        new() { ServiceCode = (byte)(serviceCode | 0x80), Status = status };

    /// <summary>
    /// Encode to MR response wire format:
    /// reply_service(1) + reserved(1) + general_status(1) + add_status_size(1) + add_status(N*2) + data.
    /// Returns the number of bytes written.
    /// </summary>
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

/// <summary>
/// Delegate signature for CIP service handlers.
/// Receives the target instance and the service request, returns a response.
/// </summary>
public delegate CipServiceResponse CipServiceHandler(CipInstance instance, CipServiceRequest request);

/// <summary>
/// Definition of a CIP service — binds a service code and name to a handler.
/// Registered on a CipClass at either the class level or instance level.
/// </summary>
public sealed class CipServiceDefinition
{
    /// <summary>CIP service code.</summary>
    public byte ServiceCode { get; }

    /// <summary>Human-readable service name (e.g. "Get_Attribute_Single").</summary>
    public string Name { get; }

    /// <summary>The handler invoked when this service is requested.</summary>
    public CipServiceHandler Handler { get; }

    public CipServiceDefinition(byte serviceCode, string name, CipServiceHandler handler)
    {
        ServiceCode = serviceCode;
        Name = name;
        Handler = handler;
    }
}
