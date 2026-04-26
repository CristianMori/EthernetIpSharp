using System.Buffers.Binary;
using System.Text;
using EipSim.Cip;

namespace EipSim.Logix;

/// <summary>
/// CIP Template Object (Class 0x6C).
/// Each UDT/structure type has one instance. Provides:
/// - Get_Attribute_List (0x03): returns struct handle, member count, definition size, struct size
/// - Template Read (0x4C): returns member information (type, offset, names)
/// </summary>
public sealed class TemplateObject
{
    public const uint ClassCode = 0x6C;

    private readonly ITagDatabase _tags;

    public CipClass CipClass { get; }

    public TemplateObject(ITagDatabase tags)
    {
        _tags = tags;
        CipClass = new CipClass(ClassCode, "Template", revision: 1);

        // Instance-level services
        CipClass.AddInstanceService(new CipServiceDefinition(
            0x03, "Get_Attribute_List", HandleGetAttributeList));
        CipClass.AddInstanceService(new CipServiceDefinition(
            0x4C, "Template_Read", HandleTemplateRead));
        CipClass.AddStandardInstanceServices();
    }

    /// <summary>Ensure a CIP instance exists for a template definition.</summary>
    public void EnsureInstance(TemplateDefinition template)
    {
        if (CipClass.GetInstance(template.InstanceId) != null) return;

        var inst = CipClass.CreateInstance(template.InstanceId);
        inst.UserData = template;

        // Attribute 1: Structure Handle (UINT)
        inst.AddAttribute(CipAttribute.Create(1, CipDataType.Uint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, template.StructureHandle));

        // Attribute 2: Member Count (UINT)
        inst.AddAttribute(CipAttribute.Create(2, CipDataType.Uint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, (ushort)template.MemberCount));

        // Attribute 4: Template Object Definition Size (UDINT) — in 32-bit words
        inst.AddAttribute(CipAttribute.Create(4, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, template.DefinitionSize));

        // Attribute 5: Template Structure Size (UDINT) — bytes on wire
        inst.AddAttribute(CipAttribute.Create(5, CipDataType.Udint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, template.StructureSize));
    }

    /// <summary>
    /// Get_Attribute_List (0x03) on a template instance.
    /// Request: attr_count (UINT) + attr_ids[]
    /// Response: count (UINT) + [attr_id (UINT) + status (UINT) + data]...
    /// </summary>
    private CipServiceResponse HandleGetAttributeList(CipInstance instance, CipServiceRequest request)
    {
        if (request.Data.Length < 2)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));

        var span = request.Data.Span;
        ushort attrCount = BinaryPrimitives.ReadUInt16LittleEndian(span);

        if (request.Data.Length < 2 + attrCount * 2)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x1C));

        var buffer = new byte[512];
        int offset = 0;

        // Count of items
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), attrCount);
        offset += 2;

        for (int i = 0; i < attrCount; i++)
        {
            ushort attrId = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2 + i * 2));

            // Attribute ID
            BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), attrId);
            offset += 2;

            var attr = instance.GetAttribute(attrId);
            if (attr != null)
            {
                // Status: success
                BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), 0);
                offset += 2;
                // Attribute data
                offset += attr.EncodeTo(buffer.AsSpan(offset));
            }
            else
            {
                // Status: attribute not supported
                BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), 0x0014);
                offset += 2;
            }
        }

        return CipServiceResponse.Success(request.ServiceCode, buffer.AsMemory(0, offset));
    }

    /// <summary>
    /// Template Read (0x4C on Template Object).
    /// Request: byte_offset (UDINT) + bytes_to_read (UINT)
    /// Response: template definition data (member info + names)
    ///
    /// The template definition structure contains:
    /// - For each member: type_info (UINT) + info (UINT) + offset (UDINT)
    ///   where type_info upper 16 bits = data type, lower 16 bits = array size or bit position
    /// - After all members: null-terminated template name + null-terminated member names
    /// </summary>
    private CipServiceResponse HandleTemplateRead(CipInstance instance, CipServiceRequest request)
    {
        var template = instance.UserData as TemplateDefinition;
        if (template == null)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x05));

        if (request.Data.Length < 6)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));

        var span = request.Data.Span;
        uint byteOffset = BinaryPrimitives.ReadUInt32LittleEndian(span);
        ushort bytesToRead = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(4));

        // Build the full template definition data
        var fullData = BuildTemplateDefinitionData(template);

        if (byteOffset >= (uint)fullData.Length)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0xFF, 0x2105));

        int available = fullData.Length - (int)byteOffset;
        int chunkSize = Math.Min(available, bytesToRead);
        chunkSize = Math.Min(chunkSize, 480); // Max reply size

        var responseData = fullData.AsMemory((int)byteOffset, chunkSize);
        bool moreData = (int)byteOffset + chunkSize < fullData.Length;

        if (moreData)
        {
            return new CipServiceResponse
            {
                ServiceCode = (byte)(request.ServiceCode | 0x80),
                Status = CipStatus.Error(0x06),
                Data = responseData,
            };
        }

        return CipServiceResponse.Success(request.ServiceCode, responseData);
    }

    /// <summary>
    /// Build the template definition byte array.
    /// Format per member: [type_and_info (4 bytes)] [offset (4 bytes)]
    /// Then: template_name\0 + member1_name\0 + member2_name\0 + ...
    /// </summary>
    private static byte[] BuildTemplateDefinitionData(TemplateDefinition template)
    {
        // Calculate total size
        int memberInfoSize = template.MemberCount * 8; // 4 bytes type+info + 4 bytes offset per member
        int nameBytes = template.Name.Length + 1; // null-terminated template name
        foreach (var m in template.Members)
            nameBytes += m.Name.Length + 1;

        int totalSize = memberInfoSize + nameBytes;
        // Pad to 4-byte boundary
        totalSize = (totalSize + 3) / 4 * 4;

        var data = new byte[totalSize];
        int offset = 0;

        // Member info entries
        foreach (var member in template.Members)
        {
            // Lower 16 bits: INFO value
            // - Atomic: 0
            // - Array: array size
            // - Bool: bit position
            ushort infoValue = member.ArraySize > 0 ? (ushort)member.ArraySize : (ushort)0;

            // Upper 16 bits: data type
            ushort typeValue = member.DataType;

            // Pack as UDINT: upper 16 = type, lower 16 = info
            uint typeAndInfo = (uint)(typeValue << 16) | infoValue;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), typeAndInfo);
            offset += 4;

            // Member offset in structure
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), (uint)member.Offset);
            offset += 4;
        }

        // Template name (null-terminated)
        Encoding.ASCII.GetBytes(template.Name, data.AsSpan(offset));
        offset += template.Name.Length;
        data[offset++] = 0;

        // Member names (null-terminated)
        foreach (var member in template.Members)
        {
            Encoding.ASCII.GetBytes(member.Name, data.AsSpan(offset));
            offset += member.Name.Length;
            data[offset++] = 0;
        }

        return data;
    }
}
