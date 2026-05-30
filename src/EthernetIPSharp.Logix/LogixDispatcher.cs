using System.Collections.Concurrent;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Logix;

/// <summary>
/// CipDispatcher subclass that models a Logix 5000 controller.
/// Handles symbolic segment addressing by overriding OnUnhandled.
/// Registers Symbol Object (0x6B) and Template Object (0x6C).
/// Caches tag references by symbolic name to avoid dictionary lookup on every request.
/// </summary>
public class LogixDispatcher : CipDispatcher
{
    public ITagDatabase Tags { get; }

    private readonly SymbolObject _symbolObject;
    private readonly TemplateObject _templateObject;

    /// <summary>Cache of tag references by symbolic name — avoids repeated dictionary lookup.</summary>
    private readonly ConcurrentDictionary<string, Tag> _symbolCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Convenience constructor using default implementations.</summary>
    public LogixDispatcher() : this(new TagDatabase()) { }

    /// <summary>DI constructor — inject a custom tag database (or mock).</summary>
    public LogixDispatcher(ITagDatabase tags) : this(tags, null) { }

    /// <summary>Full constructor — inject tag database and optional device identity.</summary>
    public LogixDispatcher(ITagDatabase tags, IdentityInfo? identity)
    {
        Tags = tags;
        _symbolObject = new SymbolObject(tags);
        _templateObject = new TemplateObject(tags);

        RegisterClass(_symbolObject.CipClass);
        RegisterClass(_templateObject.CipClass);

        // Message Router with Multiple Service Packet
        var messageRouter = new CipClass(0x02, "Message Router", revision: 1);
        messageRouter.AddStandardInstanceServices();
        messageRouter.CreateInstance(1);
        messageRouter.AddInstanceService(new CipServiceDefinition(
            MultiServiceHandler.ServiceCode, "Multiple_Service_Packet",
            (inst, req) => MultiServiceHandler.Handle(this, req)));
        RegisterClass(messageRouter);

        // Connection Manager with Unconnected Send support
        var connMgr = new EthernetIPSharp.Connections.ConnectionManagerObject();
        connMgr.DispatchRequest = (svc, path, data) => Dispatch(svc, path, data);
        RegisterClass(connMgr.CipClass);

        // Identity object (required for get_plc_info / Unconnected Send to Identity)
        if (identity != null)
        {
            var idClass = new CipClass(IdentityInfo.ClassCode, "Identity", revision: 1);
            idClass.AddStandardInstanceServices();
            var idInst = idClass.CreateInstance(1);
            idInst.AddAttribute(CipAttribute.Create(1, CipDataType.Uint, AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.VendorId));
            idInst.AddAttribute(CipAttribute.Create(2, CipDataType.Uint, AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.DeviceType));
            idInst.AddAttribute(CipAttribute.Create(3, CipDataType.Uint, AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.ProductCode));
            idInst.AddAttribute(new CipAttribute(4, CipDataType.Usint, AttributeAccess.GetSingle | AttributeAccess.GetAll, [identity.MajorRevision, identity.MinorRevision]));
            idInst.AddAttribute(CipAttribute.Create(5, CipDataType.Word, AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.Status));
            idInst.AddAttribute(CipAttribute.Create(6, CipDataType.Udint, AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.SerialNumber));
            idInst.AddAttribute(CipAttribute.CreateShortString(7, AttributeAccess.GetSingle | AttributeAccess.GetAll, identity.ProductName));
            RegisterClass(idClass);

            // Program Name object (Class 0x64, Rockwell KB 23341). pycomm3
            // queries this during connect via GetAttributesAll to populate
            // LogixDriver.info["name"]. Attribute 1 = controller program
            // name as CIP STRING (UINT length + ASCII chars).
            var pnClass = new CipClass(0x64, "Program Name", revision: 1);
            pnClass.AddStandardInstanceServices();
            var pnInst = pnClass.CreateInstance(1);
            var pnBytes = System.Text.Encoding.ASCII.GetBytes(identity.ProductName);
            var pnData = new byte[2 + pnBytes.Length];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(pnData, (ushort)pnBytes.Length);
            pnBytes.CopyTo(pnData.AsSpan(2));
            pnInst.AddAttribute(new CipAttribute(1, CipDataType.String,
                AttributeAccess.GetSingle | AttributeAccess.GetAll, pnData));
            RegisterClass(pnClass);
        }

        // Auto-register CIP instances when tags/templates are added
        tags.TagAdded += OnTagAdded;
        tags.TemplateAdded += template => _templateObject.EnsureInstance(template);

        // Sync any tags/templates that already exist in the database
        SyncCipInstances();
    }

    private void OnTagAdded(Tag tag)
    {
        _symbolObject.EnsureInstance(tag);
        // Pre-populate cache so even the first request is fast
        _symbolCache[tag.Name] = tag;
    }

    /// <summary>Ensure CIP instances exist for all tags and templates.</summary>
    public void SyncCipInstances()
    {
        foreach (var tag in Tags.AllTags)
        {
            _symbolObject.EnsureInstance(tag);
            _symbolCache[tag.Name] = tag;
        }
        foreach (var template in Tags.AllTemplates)
            _templateObject.EnsureInstance(template);
    }

    protected override CipServiceResponse OnUnhandled(byte serviceCode, CipPath path,
        ReadOnlyMemory<byte> data, byte defaultStatus = CipStatus.PathDestinationUnknown)
    {
        if (path.SymbolicName != null)
        {
            // Fast path: check cache first
            if (!_symbolCache.TryGetValue(path.SymbolicName, out var tag))
            {
                // Cache miss: look up and cache
                tag = Tags.FindByName(path.SymbolicName);
                if (tag == null)
                    return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x05));
                _symbolCache[path.SymbolicName] = tag;
            }

            return DispatchTagService(tag, serviceCode, data, path);
        }

        return base.OnUnhandled(serviceCode, path, data, defaultStatus);
    }

    internal static CipServiceResponse DispatchTagService(Tag tag, byte serviceCode,
        ReadOnlyMemory<byte> data, CipPath path)
    {
        int elementOffset = (int)(path.ElementId ?? 0);
        return serviceCode switch
        {
            TagServices.ReadTag => TagServices.HandleReadTag(tag, serviceCode, data, elementOffset),
            TagServices.WriteTag => TagServices.HandleWriteTag(tag, serviceCode, data, elementOffset),
            TagServices.ReadTagFragmented => TagServices.HandleReadTagFragmented(tag, serviceCode, data),
            TagServices.WriteTagFragmented => TagServices.HandleWriteTagFragmented(tag, serviceCode, data),
            TagServices.ReadModifyWrite => TagServices.HandleReadModifyWrite(tag, serviceCode, data),
            _ => CipServiceResponse.Error(serviceCode, CipStatus.Error(CipStatus.ServiceNotSupported)),
        };
    }
}
