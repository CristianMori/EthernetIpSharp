using System.Buffers;

namespace EthernetIPSharp.Cip;

/// <summary>
/// Standard CIP service handler implementations reused across all object classes.
/// Provides GetAttributeSingle (0x0E), SetAttributeSingle (0x10), and GetAttributeAll (0x01).
/// </summary>
public static class CipStandardServices
{
    /// <summary>Service code: Get Attributes All (0x01).</summary>
    public const byte GetAttributeAll = 0x01;
    /// <summary>Service code: Set Attributes All (0x02).</summary>
    public const byte SetAttributeAll = 0x02;
    /// <summary>Service code: Get Attribute List (0x03).</summary>
    public const byte GetAttributeList = 0x03;
    /// <summary>Service code: Set Attribute List (0x04).</summary>
    public const byte SetAttributeList = 0x04;
    /// <summary>Service code: Reset (0x05).</summary>
    public const byte Reset = 0x05;
    /// <summary>Service code: Get Attribute Single (0x0E).</summary>
    public const byte GetAttributeSingle = 0x0E;
    /// <summary>Service code: Set Attribute Single (0x10).</summary>
    public const byte SetAttributeSingle = 0x10;

    /// <summary>
    /// Handle GetAttributeSingle (0x0E) — read one attribute by ID from the path.
    /// Returns the attribute data on success, or an error if the attribute doesn't exist
    /// or isn't readable.
    /// </summary>
    public static CipServiceResponse HandleGetAttributeSingle(CipInstance instance, CipServiceRequest request)
    {
        var attrId = request.Path.AttributeId;
        if (attrId == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.PathSegmentError));

        var attr = instance.GetAttribute(attrId.Value);
        if (attr == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.AttributeNotSupported));

        if ((attr.Access & AttributeAccess.GetSingle) == 0)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.AttributeNotSupported));

        var data = new byte[attr.DataLength];
        attr.EncodeTo(data);
        return CipServiceResponse.Success(request.ServiceCode, data);
    }

    /// <summary>
    /// Handle SetAttributeSingle (0x10) — write one attribute by ID from the path.
    /// Returns success if the attribute exists and is writable, or an error otherwise.
    /// </summary>
    public static CipServiceResponse HandleSetAttributeSingle(CipInstance instance, CipServiceRequest request)
    {
        var attrId = request.Path.AttributeId;
        if (attrId == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.PathSegmentError));

        var attr = instance.GetAttribute(attrId.Value);
        if (attr == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.AttributeNotSupported));

        if ((attr.Access & AttributeAccess.SetSingle) == 0)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.AttributeNotSettable));

        attr.SetData(request.Data.Span);
        return CipServiceResponse.Success(request.ServiceCode);
    }

    /// <summary>
    /// Handle GetAttributeAll (0x01) — return all gettable attributes in ID order.
    /// Uses ArrayPool to avoid per-call heap allocation.
    /// </summary>
    public static CipServiceResponse HandleGetAttributeAll(CipInstance instance, CipServiceRequest request)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            int len = instance.EncodeAllAttributes(buffer);
            var result = buffer.AsSpan(0, len).ToArray();
            return CipServiceResponse.Success(request.ServiceCode, result);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
