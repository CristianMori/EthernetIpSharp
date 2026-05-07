using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Device;

/// <summary>
/// CIP Identity Object (Class 0x01). Required by all EtherNet/IP devices.
/// Instance 1 holds device identity attributes per Vol1 Chapter 5.
/// </summary>
public static class IdentityObject
{
    /// <summary>CIP class code for Identity.</summary>
    public const uint ClassCode = 0x01;

    /// <summary>
    /// Create an Identity CIP class with instance 1 populated from the given identity info.
    /// Registers standard Get/Set services and the Reset service (no-op for simulator).
    /// </summary>
    public static CipClass Create(IdentityInfo identity)
    {
        var cls = new CipClass(ClassCode, "Identity", revision: 1);
        cls.AddStandardInstanceServices();

        // Reset service — no-op for a simulator, returns success
        cls.AddInstanceService(new CipServiceDefinition(CipStandardServices.Reset, "Reset", HandleReset));

        var inst = cls.CreateInstance(1);

        // Attribute 1: Vendor ID (UINT)
        inst.AddAttribute(CipAttribute.Create(1, CipDataType.Uint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.VendorId));

        // Attribute 2: Device Type (UINT)
        inst.AddAttribute(CipAttribute.Create(2, CipDataType.Uint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.DeviceType));

        // Attribute 3: Product Code (UINT)
        inst.AddAttribute(CipAttribute.Create(3, CipDataType.Uint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.ProductCode));

        // Attribute 4: Revision (USINT[2] — major, minor)
        inst.AddAttribute(new CipAttribute(4, CipDataType.Usint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll,
            [identity.MajorRevision, identity.MinorRevision]));

        // Attribute 5: Status (WORD)
        inst.AddAttribute(CipAttribute.Create(5, CipDataType.Word,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.Status));

        // Attribute 6: Serial Number (UDINT)
        inst.AddAttribute(CipAttribute.Create(6, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.SerialNumber));

        // Attribute 7: Product Name (SHORT_STRING)
        inst.AddAttribute(CipAttribute.CreateShortString(7,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.ProductName));

        return cls;
    }

    private static CipServiceResponse HandleReset(CipInstance instance, CipServiceRequest request)
    {
        return CipServiceResponse.Success(request.ServiceCode);
    }
}
