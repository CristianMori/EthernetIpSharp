using System.Buffers.Binary;
using EipSim.Cip;

namespace EipSim.Logix;

/// <summary>
/// CIP Symbol Object (Class 0x6B).
/// Each tag in the controller is an instance of this class.
/// Supports Read/Write Tag services at the instance level,
/// and Get_Instance_Attribute_List (0x55) at the class level for tag browsing.
/// </summary>
public sealed class SymbolObject
{
    public const uint ClassCode = 0x6B;
    public const byte GetInstanceAttributeList = 0x55;

    private readonly ITagDatabase _tags;

    public CipClass CipClass { get; }

    public SymbolObject(ITagDatabase tags)
    {
        _tags = tags;
        CipClass = new CipClass(ClassCode, "Symbol", revision: 1);

        // Instance-level services: Read/Write Tag (routed via Symbol Instance addressing)
        CipClass.AddInstanceService(new CipServiceDefinition(
            TagServices.ReadTag, "Read_Tag", HandleInstanceReadTag));
        CipClass.AddInstanceService(new CipServiceDefinition(
            TagServices.WriteTag, "Write_Tag", HandleInstanceWriteTag));
        CipClass.AddInstanceService(new CipServiceDefinition(
            TagServices.ReadTagFragmented, "Read_Tag_Fragmented", HandleInstanceReadTagFragmented));
        CipClass.AddInstanceService(new CipServiceDefinition(
            TagServices.WriteTagFragmented, "Write_Tag_Fragmented", HandleInstanceWriteTagFragmented));
        CipClass.AddInstanceService(new CipServiceDefinition(
            TagServices.ReadModifyWrite, "Read_Modify_Write", HandleInstanceReadModifyWrite));

        // Class-level service: Get_Instance_Attribute_List for tag browsing
        CipClass.AddClassService(new CipServiceDefinition(
            GetInstanceAttributeList, "Get_Instance_Attribute_List", HandleGetInstanceAttributeList));
    }

    /// <summary>
    /// Ensure a CIP instance exists for a tag. Called when tags are added to the database.
    /// This creates the CipInstance if it doesn't exist, and sets UserData to the Tag.
    /// </summary>
    public void EnsureInstance(Tag tag)
    {
        var existing = CipClass.GetInstance(tag.InstanceId);
        if (existing != null) return;

        var inst = CipClass.CreateInstance(tag.InstanceId);
        inst.UserData = tag;

        // Attribute 1: Symbol Name (STRING: UINT length + chars)
        var nameData = new byte[2 + tag.Name.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(nameData, (ushort)tag.Name.Length);
        System.Text.Encoding.ASCII.GetBytes(tag.Name, nameData.AsSpan(2));
        inst.AddAttribute(new CipAttribute(1, CipDataType.String,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, nameData));

        // Attribute 2: Symbol Type (WORD)
        inst.AddAttribute(CipAttribute.Create(2, CipDataType.Word,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, tag.SymbolType));
    }

    private Tag? GetTagFromInstance(CipInstance instance) =>
        instance.UserData as Tag ?? _tags.FindByInstanceId(instance.InstanceId);

    // --- Instance service handlers ---

    private CipServiceResponse HandleInstanceReadTag(CipInstance instance, CipServiceRequest request)
    {
        var tag = GetTagFromInstance(instance);
        if (tag == null) return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x05));
        return TagServices.HandleReadTag(tag, request.ServiceCode, request.Data);
    }

    private CipServiceResponse HandleInstanceWriteTag(CipInstance instance, CipServiceRequest request)
    {
        var tag = GetTagFromInstance(instance);
        if (tag == null) return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x05));
        return TagServices.HandleWriteTag(tag, request.ServiceCode, request.Data);
    }

    private CipServiceResponse HandleInstanceReadTagFragmented(CipInstance instance, CipServiceRequest request)
    {
        var tag = GetTagFromInstance(instance);
        if (tag == null) return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x05));
        return TagServices.HandleReadTagFragmented(tag, request.ServiceCode, request.Data);
    }

    private CipServiceResponse HandleInstanceWriteTagFragmented(CipInstance instance, CipServiceRequest request)
    {
        var tag = GetTagFromInstance(instance);
        if (tag == null) return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x05));
        return TagServices.HandleWriteTagFragmented(tag, request.ServiceCode, request.Data);
    }

    private CipServiceResponse HandleInstanceReadModifyWrite(CipInstance instance, CipServiceRequest request)
    {
        var tag = GetTagFromInstance(instance);
        if (tag == null) return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x05));
        return TagServices.HandleReadModifyWrite(tag, request.ServiceCode, request.Data);
    }

    // --- Class-level service: Get_Instance_Attribute_List (0x55) ---

    /// <summary>
    /// Paginated tag enumeration. Request path instance ID is the starting instance.
    /// Request data: attr_count (UINT) + attr_id[] (UINT each)
    /// Response: packed [instance_id (UDINT) + attr_data...] per tag. Status 0x06 if more.
    /// </summary>
    private CipServiceResponse HandleGetInstanceAttributeList(CipInstance classInstance, CipServiceRequest request)
    {
        if (request.Data.Length < 2)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));

        var span = request.Data.Span;
        ushort attrCount = BinaryPrimitives.ReadUInt16LittleEndian(span);

        if (request.Data.Length < 2 + attrCount * 2)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));

        // Parse requested attribute IDs
        var requestedAttrs = new ushort[attrCount];
        for (int i = 0; i < attrCount; i++)
            requestedAttrs[i] = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2 + i * 2));

        // Starting instance from the request path
        uint startInstance = request.Path.InstanceId ?? 0;

        // Get all tags sorted by instance ID, starting after startInstance
        var tags = _tags.AllTags
            .Where(t => t.InstanceId > startInstance)
            .OrderBy(t => t.InstanceId)
            .ToList();

        // Ensure all tags have CIP instances
        foreach (var tag in tags)
            EnsureInstance(tag);

        // Pack response
        var buffer = new byte[4096];
        int offset = 0;
        int tagsPacked = 0;
        const int maxResponseSize = 480;

        foreach (var tag in tags)
        {
            // Estimate size for this tag entry
            int entryStart = offset;

            // Instance ID (UDINT)
            if (offset + 4 > maxResponseSize && tagsPacked > 0) break;
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset), tag.InstanceId);
            offset += 4;

            // Pack requested attributes
            foreach (var attrId in requestedAttrs)
            {
                switch (attrId)
                {
                    case 1: // Symbol Name (STRING: UINT length + chars)
                        int nameEntrySize = 2 + tag.Name.Length;
                        if (offset + nameEntrySize > maxResponseSize && tagsPacked > 0)
                        {
                            offset = entryStart; // Roll back this tag
                            goto done;
                        }
                        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), (ushort)tag.Name.Length);
                        offset += 2;
                        System.Text.Encoding.ASCII.GetBytes(tag.Name, buffer.AsSpan(offset));
                        offset += tag.Name.Length;
                        break;

                    case 2: // Symbol Type (WORD)
                        if (offset + 2 > maxResponseSize && tagsPacked > 0)
                        {
                            offset = entryStart;
                            goto done;
                        }
                        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), tag.SymbolType);
                        offset += 2;
                        break;
                }
            }

            tagsPacked++;
        }

        done:
        bool moreData = tagsPacked < tags.Count;

        if (moreData)
        {
            return new CipServiceResponse
            {
                ServiceCode = (byte)(request.ServiceCode | 0x80),
                Status = CipStatus.Error(0x06), // More data
                Data = buffer.AsMemory(0, offset),
            };
        }

        return CipServiceResponse.Success(request.ServiceCode, buffer.AsMemory(0, offset));
    }
}
