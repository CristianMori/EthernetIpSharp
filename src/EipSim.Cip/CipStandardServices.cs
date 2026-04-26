namespace EipSim.Cip;

/// <summary>
/// Standard CIP service implementations reused across all object classes.
/// </summary>
public static class CipStandardServices
{
    public const byte GetAttributeAll = 0x01;
    public const byte SetAttributeAll = 0x02;
    public const byte GetAttributeList = 0x03;
    public const byte SetAttributeList = 0x04;
    public const byte Reset = 0x05;
    public const byte GetAttributeSingle = 0x0E;
    public const byte SetAttributeSingle = 0x10;

    public static CipServiceResponse HandleGetAttributeSingle(CipInstance instance, CipServiceRequest request)
    {
        // Request data should contain the attribute ID in the path
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

    public static CipServiceResponse HandleGetAttributeAll(CipInstance instance, CipServiceRequest request)
    {
        var buffer = new byte[4096];
        int len = instance.EncodeAllAttributes(buffer);
        return CipServiceResponse.Success(request.ServiceCode, buffer.AsMemory(0, len));
    }
}
