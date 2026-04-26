namespace EipSim.Cip;

public readonly struct CipStatus
{
    public byte GeneralStatus { get; init; }
    public ushort[] AdditionalStatus { get; init; }

    public bool IsSuccess => GeneralStatus == 0;

    public static readonly CipStatus Success = new() { GeneralStatus = 0, AdditionalStatus = [] };

    public static CipStatus Error(byte general, params ushort[] additional) =>
        new() { GeneralStatus = general, AdditionalStatus = additional };

    // Common CIP general status codes
    public const byte PathSegmentError = 0x04;
    public const byte PathDestinationUnknown = 0x05;
    public const byte ServiceNotSupported = 0x08;
    public const byte InvalidAttributeValue = 0x09;
    public const byte AttributeNotSettable = 0x0E;
    public const byte NotEnoughData = 0x13;
    public const byte AttributeNotSupported = 0x14;
    public const byte TooMuchData = 0x15;
    public const byte ObjectDoesNotExist = 0x16;
    public const byte InvalidParameter = 0x20;

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
