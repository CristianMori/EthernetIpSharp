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
        // Prefer the ordered Segments list when it carries a symbolic root plus
        // post-root drilling. Otherwise fall back to the flat SymbolicName lookup
        // for back-compat with callers that build CipPath via an object initializer
        // without segments. Paths with only logical segments (Class/Instance) fall
        // through to base.OnUnhandled so class-instance dispatch runs.
        var segs = path.Segments;
        int firstSymIdx = FindFirstSymbolic(segs);
        if (firstSymIdx >= 0)
        {
            var firstSymName = ((SymbolicPathSegment)segs[firstSymIdx]).Name;

            // Program-scope prefix: "Program:MainProgram" selects the program's own
            // tag table; the next symbolic segment names the root tag inside it.
            if (firstSymName.StartsWith("Program:", StringComparison.OrdinalIgnoreCase))
            {
                var programName = firstSymName.Substring("Program:".Length);
                var program = Tags.FindProgram(programName);
                if (program == null)
                    return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x05));

                int rootSymIdx = FindNextSymbolic(segs, firstSymIdx + 1);
                if (rootSymIdx < 0)
                    return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x05));

                var rootName = ((SymbolicPathSegment)segs[rootSymIdx]).Name;
                var programTag = program.FindByName(rootName);
                if (programTag == null)
                    return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x05));

                var postProgram = CollectPostRoot(segs, rootSymIdx);
                if (postProgram.Count == 0)
                    return DispatchTagService(programTag, serviceCode, data, path);

                if (!TagPathWalker.TryWalk(programTag, postProgram, Tags.FindTemplate, out var pwalked, out _))
                    return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x05));
                return DispatchTagServiceWalked(programTag, serviceCode, data, pwalked);
            }

            var rootName2 = firstSymName;
            if (!_symbolCache.TryGetValue(rootName2, out var tag))
            {
                tag = Tags.FindByName(rootName2);
                if (tag == null)
                    return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x05));
                _symbolCache[rootName2] = tag;
            }

            // Collect post-root segments (member drilling / element indexing).
            // Logical segments interleaved with symbolics are ignored — the class
            // dispatcher already picked those up.
            var postRoot = CollectPostRoot(segs, firstSymIdx);
            if (postRoot.Count == 0)
                return DispatchTagService(tag, serviceCode, data, path);

            if (!TagPathWalker.TryWalk(tag, postRoot, Tags.FindTemplate, out var walked, out _))
                return CipServiceResponse.Error(serviceCode, CipStatus.Error(0x05));

            return DispatchTagServiceWalked(tag, serviceCode, data, walked);
        }

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

    private static int FindFirstSymbolic(IReadOnlyList<CipPathSegment> segs)
    {
        for (int i = 0; i < segs.Count; i++)
            if (segs[i] is SymbolicPathSegment) return i;
        return -1;
    }

    private static int FindNextSymbolic(IReadOnlyList<CipPathSegment> segs, int from)
    {
        for (int i = from; i < segs.Count; i++)
            if (segs[i] is SymbolicPathSegment) return i;
        return -1;
    }

    private static List<CipPathSegment> CollectPostRoot(IReadOnlyList<CipPathSegment> segs, int firstSymIdx)
    {
        var post = new List<CipPathSegment>(Math.Max(0, segs.Count - firstSymIdx - 1));
        for (int i = firstSymIdx + 1; i < segs.Count; i++)
        {
            if (segs[i] is LogicalPathSegment) continue;
            post.Add(segs[i]);
        }
        return post;
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

    internal static CipServiceResponse DispatchTagServiceWalked(Tag tag, byte serviceCode,
        ReadOnlyMemory<byte> data, TagPathWalker.WalkResult walked)
    {
        return serviceCode switch
        {
            TagServices.ReadTag => TagServices.HandleReadTagAt(tag, serviceCode, data, walked),
            TagServices.WriteTag => TagServices.HandleWriteTagAt(tag, serviceCode, data, walked),
            TagServices.ReadTagFragmented => TagServices.HandleReadTagFragmentedAt(tag, serviceCode, data, walked),
            TagServices.WriteTagFragmented => TagServices.HandleWriteTagFragmentedAt(tag, serviceCode, data, walked),
            TagServices.ReadModifyWrite => TagServices.HandleReadModifyWriteAt(tag, serviceCode, data, walked),
            _ => CipServiceResponse.Error(serviceCode, CipStatus.Error(CipStatus.ServiceNotSupported)),
        };
    }
}
