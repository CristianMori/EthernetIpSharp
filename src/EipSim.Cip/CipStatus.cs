namespace EipSim.Cip;

/// <summary>
/// CIP service response status — general status byte plus optional additional status words.
/// Encoded in the MR response after the reply service code and reserved byte.
/// </summary>
public readonly struct CipStatus
{
    /// <summary>General status code (0 = success).</summary>
    public byte GeneralStatus { get; init; }

    /// <summary>Optional additional status words providing more detail about the error.</summary>
    public ushort[] AdditionalStatus { get; init; }

    /// <summary>True if GeneralStatus is 0 (success).</summary>
    public bool IsSuccess => GeneralStatus == 0;

    /// <summary>Pre-built success status.</summary>
    public static readonly CipStatus Success = new() { GeneralStatus = 0, AdditionalStatus = [] };

    /// <summary>Create an error status with optional additional status words.</summary>
    public static CipStatus Error(byte general, params ushort[] additional) =>
        new() { GeneralStatus = general, AdditionalStatus = additional };

    // --- Common CIP general status codes ---

    /// <summary>0x04 — syntax error in request path.</summary>
    public const byte PathSegmentError = 0x04;
    /// <summary>0x05 — request path destination unknown.</summary>
    public const byte PathDestinationUnknown = 0x05;
    /// <summary>0x08 — service not supported by the target object.</summary>
    public const byte ServiceNotSupported = 0x08;
    /// <summary>0x09 — invalid attribute value.</summary>
    public const byte InvalidAttributeValue = 0x09;
    /// <summary>0x0E — attribute is read-only.</summary>
    public const byte AttributeNotSettable = 0x0E;
    /// <summary>0x13 — insufficient data in the request.</summary>
    public const byte NotEnoughData = 0x13;
    /// <summary>0x14 — attribute not supported.</summary>
    public const byte AttributeNotSupported = 0x14;
    /// <summary>0x15 — too much data in the request.</summary>
    public const byte TooMuchData = 0x15;
    /// <summary>0x16 — object (instance) does not exist.</summary>
    public const byte ObjectDoesNotExist = 0x16;
    /// <summary>0x20 — invalid parameter.</summary>
    public const byte InvalidParameter = 0x20;

    /// <summary>
    /// Encode to wire format: general_status(1) + additional_status_size(1) + additional_status(N*2).
    /// Returns the number of bytes written.
    /// </summary>
    public int Encode(Span<byte> dst)
    {
        int offset = 0;
        dst[offset++] = GeneralStatus;
        var additional = AdditionalStatus ?? [];
        dst[offset++] = (byte)additional.Length;
        foreach (var s in additional)
        {
            CipDataSerializer.WriteUint(dst.Slice(offset), s);
            offset += 2;
        }
        return offset;
    }
}
