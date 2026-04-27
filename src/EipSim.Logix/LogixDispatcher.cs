using System.Collections.Concurrent;
using EipSim.Cip;

namespace EipSim.Logix;

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
    public LogixDispatcher(ITagDatabase tags)
    {
        Tags = tags;
        _symbolObject = new SymbolObject(tags);
        _templateObject = new TemplateObject(tags);

        RegisterClass(_symbolObject.CipClass);
        RegisterClass(_templateObject.CipClass);

        var messageRouter = new CipClass(0x02, "Message Router", revision: 1);
        messageRouter.AddStandardInstanceServices();
        messageRouter.CreateInstance(1);
        messageRouter.AddInstanceService(new CipServiceDefinition(
            MultiServiceHandler.ServiceCode, "Multiple_Service_Packet",
            (inst, req) => MultiServiceHandler.Handle(this, req)));
        RegisterClass(messageRouter);

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

    protected override CipServiceResponse OnUnhandled(byte serviceCode, CipPath path, ReadOnlyMemory<byte> data)
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

        return base.OnUnhandled(serviceCode, path, data);
    }

    internal static CipServiceResponse DispatchTagService(Tag tag, byte serviceCode,
        ReadOnlyMemory<byte> data, CipPath path)
    {
        return serviceCode switch
        {
            TagServices.ReadTag => TagServices.HandleReadTag(tag, serviceCode, data),
            TagServices.WriteTag => TagServices.HandleWriteTag(tag, serviceCode, data),
            TagServices.ReadTagFragmented => TagServices.HandleReadTagFragmented(tag, serviceCode, data),
            TagServices.WriteTagFragmented => TagServices.HandleWriteTagFragmented(tag, serviceCode, data),
            TagServices.ReadModifyWrite => TagServices.HandleReadModifyWrite(tag, serviceCode, data),
            _ => CipServiceResponse.Error(serviceCode, CipStatus.Error(CipStatus.ServiceNotSupported)),
        };
    }
}
