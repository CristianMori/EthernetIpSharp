using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Logix;

/// <summary>
/// Client for reading and writing Logix tags over EtherNet/IP.
/// TCP only — connects, registers a session, sends CIP explicit messages via Unconnected Send.
/// No UDP, no I/O connections, no Forward Open. Just tag access.
///
/// Usage:
///   var client = new TagClient("192.168.1.10");
///   await client.ConnectAsync();
///   int rate = await client.ReadAsync&lt;int&gt;("rate");
///   await client.WriteAsync("rate", 9999);
///   var tags = await client.BrowseTagsAsync();
///   await client.DisconnectAsync();
/// </summary>
public sealed class TagClient : IAsyncDisposable
{
    private const int EipPort = 44818;

    private readonly string _host;
    private readonly int _port;
    private TcpClient? _client;
    private NetworkStream? _stream;
    private readonly SemaphoreSlim _lock = new(1, 1);

    // Instance-ID caches populated by BrowseTagsAsync. When a root tag is in
    // the cache, BuildTagPath emits a 6-byte logical Symbol Object segment
    // (Class 0x6B + 16-bit Instance) instead of the longer ANSI symbolic
    // segment. Logix accepts this form for the controller-scope leaf and for
    // the in-program tag root (but NOT for the "Program:Foo" prefix itself —
    // that stays symbolic on the wire).
    private readonly Dictionary<string, uint> _controllerAtoms = new();
    private readonly Dictionary<(string Program, string Name), uint> _programAtoms = new();

    /// <summary>Session handle assigned by the target.</summary>
    public uint SessionHandle { get; private set; }

    /// <summary>True if connected and session is registered.</summary>
    public bool IsConnected => _client?.Connected == true && SessionHandle != 0;

    /// <summary>Create a tag client for the given host and port.</summary>
    public TagClient(string host, int port = EipPort)
    {
        _host = host;
        _port = port;
    }

    /// <summary>Connect to the target and register an encapsulation session.</summary>
    public async Task ConnectAsync(CancellationToken ct = default)
    {
        _client = new TcpClient();
        await _client.ConnectAsync(_host, _port, ct);
        _stream = _client.GetStream();
        SessionHandle = await RegisterSessionAsync(ct);
    }

    /// <summary>Read a single tag value by name.</summary>
    public async Task<T> ReadAsync<T>(string tagName, CancellationToken ct = default) where T : unmanaged
    {
        var response = await ReadTagRawAsync(tagName, 1, ct);
        // response: tag_type(2) + data
        unsafe
        {
            fixed (byte* ptr = response.AsSpan(2))
                return *(T*)ptr;
        }
    }

    /// <summary>
    /// Read an entire structure tag and parse its members using the template definition.
    /// Returns a StructureValue with named member access.
    /// The template must have been obtained from BrowseTagsAsync or ReadTemplateAsync.
    /// </summary>
    public async Task<StructureValue> ReadStructAsync(string tagName, TemplateInfo template, CancellationToken ct = default)
    {
        var structData = await ReadStructBytesAsync(tagName, ct);
        return new StructureValue(template, structData);
    }

    /// <summary>Read a structure tag directly into a generated IUdtStructure type.</summary>
    public async Task<T> ReadStructAsync<T>(string tagName, CancellationToken ct = default)
        where T : IUdtStructure, new()
    {
        var structData = await ReadStructBytesAsync(tagName, ct);
        var result = new T();
        result.FromBytes(structData);
        return result;
    }

    /// <summary>
    /// Read a structure tag's body via Read_Tag_Fragmented (0x52) in a loop.
    /// Read_Tag (0x4C) is single-shot and the controller silently drops the
    /// body when the reply would exceed its packet limit; this loop handles
    /// any size. First fragment carries tag_type(2)+struct_handle(2);
    /// subsequent fragments carry just tag_type(2).
    /// </summary>
    private async Task<byte[]> ReadStructBytesAsync(string tagName, CancellationToken ct)
    {
        var path = BuildTagPath(tagName);
        var acc = new List<byte>();
        uint byteOffset = 0;
        bool first = true;

        while (true)
        {
            var req = new byte[6];
            BinaryPrimitives.WriteUInt16LittleEndian(req.AsSpan(0, 2), 1); // element_count
            BinaryPrimitives.WriteUInt32LittleEndian(req.AsSpan(2, 4), byteOffset);

            var (status, data) = await SendCipWithStatusAsync(TagServices.ReadTagFragmented, path, req, ct);
            if (status != 0x00 && status != 0x06)
                throw new InvalidOperationException($"ReadStructBytesAsync: CIP status 0x{status:X2}");

            int headerSize = first ? 4 : 2;
            if (data.Length <= headerSize) break;
            int added = data.Length - headerSize;
            acc.AddRange(data.AsSpan(headerSize).ToArray());
            byteOffset += (uint)added;
            first = false;

            if (status == 0x00) break;
        }
        return acc.ToArray();
    }

    /// <summary>Write a StructureValue to a tag.</summary>
    public async Task WriteStructValueAsync(string tagName, StructureValue value, CancellationToken ct = default)
    {
        await WriteStructAsync(tagName, value.Template.StructureHandle, 1, value.ToBytes(), ct);
    }

    /// <summary>Write a generated IUdtStructure to a tag.</summary>
    public async Task WriteStructAsync<T>(string tagName, T value, CancellationToken ct = default)
        where T : IUdtStructure
    {
        await WriteStructAsync(tagName, value.StructureHandle, 1, value.ToBytes(), ct);
    }

    /// <summary>Read a tag and return the raw response (tag_type + data bytes).</summary>
    public async Task<byte[]> ReadTagRawAsync(string tagName, ushort elementCount = 1, CancellationToken ct = default)
    {
        var path = BuildTagPath(tagName);
        var reqData = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(reqData, elementCount);

        var response = await SendCipAsync(TagServices.ReadTag, path, reqData, ct);
        return response;
    }

    /// <summary>Write a single typed value to a tag.</summary>
    public async Task WriteAsync<T>(string tagName, T value, CancellationToken ct = default) where T : unmanaged
    {
        ushort tagType = GuessTagType<T>();
        int size;
        unsafe { size = sizeof(T); }

        var data = new byte[4 + size];
        BinaryPrimitives.WriteUInt16LittleEndian(data, tagType);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), 1); // element count
        unsafe
        {
            fixed (byte* ptr = data.AsSpan(4))
                *(T*)ptr = value;
        }

        var path = BuildTagPath(tagName);
        await SendCipAsync(TagServices.WriteTag, path, data, ct);
    }

    /// <summary>
    /// Read a Logix STRING tag and return it as a .NET string.
    /// Logix STRING is a structure: LEN (DINT @ 0) + DATA (SINT[82] @ 4).
    /// This is NOT the CIP STRING type (0xD0) — Logix uses a predefined UDT.
    ///
    /// Read Tag response for a structure: tag_type(2) + struct_handle(2) + structure_data.
    /// So the actual LEN starts at byte offset 4 in the response.
    /// </summary>
    public async Task<string> ReadStringAsync(string tagName, CancellationToken ct = default)
    {
        var raw = await ReadTagRawAsync(tagName, 1, ct);
        // Response layout: tag_type(2) + struct_handle(2) + LEN(4) + DATA(82) + pad(2)
        const int headerSize = 4; // tag_type + struct_handle
        if (raw.Length < headerSize + LogixDataTypes.StringDataOffset)
            return "";

        int len = BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(headerSize + LogixDataTypes.StringLenOffset));
        if (len <= 0) return "";

        int maxLen = Math.Min(len, Math.Min(LogixDataTypes.StringMaxLength, raw.Length - headerSize - LogixDataTypes.StringDataOffset));
        return Encoding.ASCII.GetString(raw, headerSize + LogixDataTypes.StringDataOffset, maxLen);
    }

    /// <summary>
    /// Write a .NET string to a Logix STRING tag.
    /// Builds the Logix STRING structure: LEN (DINT) + DATA (SINT[82]).
    /// Requires the structure handle from the template.
    /// </summary>
    public async Task WriteStringAsync(string tagName, string value, ushort structureHandle, CancellationToken ct = default)
    {
        var strBytes = Encoding.ASCII.GetBytes(value);
        int len = Math.Min(strBytes.Length, LogixDataTypes.StringMaxLength);

        var structData = new byte[LogixDataTypes.StringStructureSize];
        BinaryPrimitives.WriteInt32LittleEndian(structData, len);
        strBytes.AsSpan(0, len).CopyTo(structData.AsSpan(LogixDataTypes.StringDataOffset));

        await WriteStructAsync(tagName, structureHandle, 1, structData, ct);
    }

    /// <summary>Write raw data to a tag with explicit tag type and element count (atomic types).</summary>
    public async Task WriteRawAsync(string tagName, ushort tagType, ushort elementCount, byte[] value, CancellationToken ct = default)
    {
        var data = new byte[4 + value.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(data, tagType);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), elementCount);
        value.CopyTo(data.AsSpan(4));

        var path = BuildTagPath(tagName);
        await SendCipAsync(TagServices.WriteTag, path, data, ct);
    }

    /// <summary>
    /// Read multiple tags in a single request using Multiple Service Packet (0x0A).
    /// Returns a dictionary of tag name → raw response bytes (tag_type + data).
    /// Much faster than individual reads when accessing many tags.
    /// </summary>
    public async Task<Dictionary<string, byte[]>> ReadMultipleAsync(IEnumerable<string> tagNames, CancellationToken ct = default)
    {
        var names = tagNames.ToList();
        if (names.Count == 0) return new();

        // Build sub-requests: each is a Read Tag MR request
        var subRequests = new List<byte[]>();
        foreach (var name in names)
        {
            var path = BuildTagPath(name);
            var reqData = new byte[] { 0x01, 0x00 }; // 1 element
            var mr = new byte[2 + path.Length + reqData.Length];
            mr[0] = TagServices.ReadTag;
            mr[1] = (byte)(path.Length / 2);
            path.CopyTo(mr.AsSpan(2));
            reqData.CopyTo(mr.AsSpan(2 + path.Length));
            subRequests.Add(mr);
        }

        var responses = await SendMultiServiceAsync(subRequests, ct);

        var result = new Dictionary<string, byte[]>();
        for (int i = 0; i < names.Count && i < responses.Count; i++)
        {
            var (status, data) = responses[i];
            if (status == 0x00 || status == 0x06)
                result[names[i]] = data;
        }
        return result;
    }

    /// <summary>
    /// Write multiple atomic tags in a single request using Multiple Service Packet (0x0A).
    /// Each entry is (tagName, tagType, value as byte[]).
    /// Returns a dictionary of tag name → success (true/false).
    /// </summary>
    public async Task<Dictionary<string, bool>> WriteMultipleAsync(
        IEnumerable<(string Name, ushort TagType, byte[] Value)> writes, CancellationToken ct = default)
    {
        var writeList = writes.ToList();
        if (writeList.Count == 0) return new();

        var subRequests = new List<byte[]>();
        foreach (var (name, tagType, value) in writeList)
        {
            var path = BuildTagPath(name);
            // Write Tag data: tag_type(2) + element_count(2) + value
            var writeData = new byte[4 + value.Length];
            BinaryPrimitives.WriteUInt16LittleEndian(writeData, tagType);
            BinaryPrimitives.WriteUInt16LittleEndian(writeData.AsSpan(2), 1);
            value.CopyTo(writeData.AsSpan(4));

            var mr = new byte[2 + path.Length + writeData.Length];
            mr[0] = TagServices.WriteTag;
            mr[1] = (byte)(path.Length / 2);
            path.CopyTo(mr.AsSpan(2));
            writeData.CopyTo(mr.AsSpan(2 + path.Length));
            subRequests.Add(mr);
        }

        var responses = await SendMultiServiceAsync(subRequests, ct);

        var result = new Dictionary<string, bool>();
        for (int i = 0; i < writeList.Count && i < responses.Count; i++)
            result[writeList[i].Name] = responses[i].status == 0x00;
        return result;
    }

    /// <summary>
    /// Send a Multiple Service Packet (0x0A) to the Message Router.
    /// Takes a list of pre-built MR sub-requests, packs them, sends, and parses responses.
    /// Returns a list of (generalStatus, responseData) per sub-request.
    /// </summary>
    private async Task<List<(byte status, byte[] data)>> SendMultiServiceAsync(
        List<byte[]> subRequests, CancellationToken ct)
    {
        // Build Multiple Service Packet request data:
        // service_count(2) + offsets[](2 each) + packed sub-requests
        int headerSize = 2 + subRequests.Count * 2;
        int totalPayload = headerSize;
        foreach (var sr in subRequests)
            totalPayload += sr.Length;

        var msData = new byte[totalPayload];
        BinaryPrimitives.WriteUInt16LittleEndian(msData, (ushort)subRequests.Count);

        // Calculate and write offsets
        int currentOffset = headerSize;
        for (int i = 0; i < subRequests.Count; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(msData.AsSpan(2 + i * 2), (ushort)currentOffset);
            currentOffset += subRequests[i].Length;
        }

        // Pack sub-requests
        int off = headerSize;
        foreach (var sr in subRequests)
        {
            sr.CopyTo(msData.AsSpan(off));
            off += sr.Length;
        }

        // Send to Message Router (class 0x02, instance 1) with service 0x0A
        var mrPath = new byte[] { 0x20, 0x02, 0x24, 0x01 };
        var (status, respData) = await SendCipWithStatusAsync(0x0A, mrPath, msData, ct);

        if (status != 0x00)
            throw new InvalidOperationException($"Multiple Service Packet failed: status=0x{status:X2}");

        // Parse response: service_count(2) + offsets[](2 each) + packed responses
        var results = new List<(byte, byte[])>();
        if (respData.Length < 2) return results;

        ushort respCount = BinaryPrimitives.ReadUInt16LittleEndian(respData);
        var respOffsets = new ushort[respCount];
        for (int i = 0; i < respCount; i++)
            respOffsets[i] = BinaryPrimitives.ReadUInt16LittleEndian(respData.AsSpan(2 + i * 2));

        for (int i = 0; i < respCount; i++)
        {
            int start = respOffsets[i];
            int end = i + 1 < respCount ? respOffsets[i + 1] : respData.Length;
            if (start + 4 > respData.Length) break;

            // Each sub-response is an MR response: service(1) + reserved(1) + status(1) + addStatusSize(1) + ...
            byte subStatus = respData[start + 2];
            byte addSize = respData[start + 3];
            int dataStart = start + 4 + addSize * 2;
            var subData = dataStart < end ? respData[dataStart..end] : [];
            results.Add((subStatus, subData));
        }

        return results;
    }

    /// <summary>
    /// Write a structure tag. The tag type parameter for structures consists of
    /// TWO 16-bit values: 0x02A0 (structure flag) + structure handle.
    /// This differs from atomic writes which use a single 16-bit tag type.
    /// </summary>
    public async Task WriteStructAsync(string tagName, ushort structureHandle, ushort elementCount, byte[] value, CancellationToken ct = default)
    {
        // Structure write: tag_type(2) = 0x02A0 + struct_handle(2) + element_count(2) + data
        var data = new byte[6 + value.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(data, 0x02A0); // structure flag
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), structureHandle);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), elementCount);
        value.CopyTo(data.AsSpan(6));

        var path = BuildTagPath(tagName);
        await SendCipAsync(TagServices.WriteTag, path, data, ct);
    }

    /// <summary>
    /// Browse all tags (controller-scope and program-scope) and resolve structure templates.
    /// Returns a TagBrowseResult containing all tags and their template definitions.
    /// Automatically discovers programs and browses their tags.
    /// </summary>
    public async Task<TagBrowseResult> BrowseTagsAsync(CancellationToken ct = default)
    {
        // Step 1: Browse controller-scope tags
        var tags = await BrowseSymbolsAsync(null, ct);

        // Cache controller-scope user tag instance IDs (skip system + __ prefix).
        foreach (var t in tags)
        {
            if (t.IsSystem) continue;
            if (t.Name.StartsWith("__")) continue;
            _controllerAtoms[t.Name] = (uint)t.InstanceId;
        }

        // Step 2: Find programs and browse their tags. Programs themselves are
        // system tags at controller scope, so they're filtered out above; we
        // pick them out of the raw browse here.
        var programs = tags
            .Where(t => t.Name.StartsWith("Program:") && !t.Name.Contains('.'))
            .Select(t => t.Name)
            .ToList();

        foreach (var program in programs)
        {
            var programTags = await BrowseSymbolsAsync(program, ct);
            foreach (var t in programTags)
            {
                if (!t.Name.StartsWith("__"))
                    _programAtoms[(program, t.Name)] = (uint)t.InstanceId;
                t.Name = $"{program}.{t.Name}";
            }
            tags.AddRange(programTags);
        }

        // Step 3: Fetch templates for all struct tags
        var templates = new Dictionary<ushort, TemplateInfo>();
        var templateIds = tags
            .Where(t => t.IsStruct)
            .Select(t => t.TypeCode)
            .Distinct()
            .ToList();

        foreach (var templateId in templateIds)
        {
            try
            {
                var template = await ReadTemplateAsync(templateId, ct);
                templates[templateId] = template;
            }
            catch { } // Skip templates we can't read
        }

        // Link templates to tags
        foreach (var tag in tags)
        {
            if (tag.IsStruct && templates.TryGetValue(tag.TypeCode, out var tmpl))
                tag.Template = tmpl;
        }

        return new TagBrowseResult { Tags = tags, Templates = templates };
    }

    /// <summary>
    /// Browse symbol instances for a given scope.
    /// Pass null for controller-scope, or "Program:MainProgram" for program-scope.
    /// </summary>
    private async Task<List<TagInfo>> BrowseSymbolsAsync(string? program, CancellationToken ct)
    {
        var tags = new List<TagInfo>();
        uint startInstance = 0;

        // Build prefix path for program scope: symbolic segment "Program:XYZ"
        byte[] programPrefix = [];
        if (program != null)
        {
            var progBytes = Encoding.ASCII.GetBytes(program);
            int padded = progBytes.Length % 2 != 0 ? progBytes.Length + 1 : progBytes.Length;
            programPrefix = new byte[2 + padded];
            programPrefix[0] = 0x91;
            programPrefix[1] = (byte)progBytes.Length;
            progBytes.CopyTo(programPrefix, 2);
        }

        while (true)
        {
            // Path: [optional program prefix] + Class 0x6B + Instance (16-bit)
            var classInstPath = new byte[6];
            classInstPath[0] = 0x20; classInstPath[1] = 0x6B;
            classInstPath[2] = 0x25; classInstPath[3] = 0x00;
            BinaryPrimitives.WriteUInt16LittleEndian(classInstPath.AsSpan(4), (ushort)startInstance);

            var path = new byte[programPrefix.Length + classInstPath.Length];
            programPrefix.CopyTo(path, 0);
            classInstPath.CopyTo(path, programPrefix.Length);

            var reqData = new byte[6];
            BinaryPrimitives.WriteUInt16LittleEndian(reqData, 2);
            BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(2), 1); // attr 1 (name)
            BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(4), 2); // attr 2 (type)

            var (status, data) = await SendCipWithStatusAsync(0x55, path, reqData, ct);

            if (status != 0x00 && status != 0x06) break;

            int off = 0;
            while (off + 6 < data.Length)
            {
                uint instId = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(off)); off += 4;
                ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
                if (off + nameLen + 2 > data.Length) break;
                string name = Encoding.ASCII.GetString(data, off, nameLen); off += nameLen;
                ushort symType = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;

                tags.Add(new TagInfo
                {
                    Name = name,
                    InstanceId = instId,
                    SymbolType = symType,
                    IsStruct = (symType & 0x8000) != 0,
                    IsSystem = (symType & 0x1000) != 0,
                    ArrayDimensions = (symType >> 13) & 0x03,
                    TypeCode = (ushort)(symType & 0x0FFF),
                });
                startInstance = instId;
            }

            if (status == 0x00) break;
            startInstance++;
        }

        return tags;
    }

    /// <summary>
    /// Read a template definition from the controller.
    /// Fetches attributes (handle, member count, sizes) then reads the member info and names.
    /// </summary>
    public async Task<TemplateInfo> ReadTemplateAsync(ushort templateInstanceId, CancellationToken ct = default)
    {
        // Step 1: Get template attributes (1=handle, 2=member_count, 4=def_size, 5=struct_size)
        var attrPath = new byte[6];
        attrPath[0] = 0x20; attrPath[1] = 0x6C; // Class 0x6C (Template)
        attrPath[2] = 0x25; attrPath[3] = 0x00;
        BinaryPrimitives.WriteUInt16LittleEndian(attrPath.AsSpan(4), templateInstanceId);

        var attrReqData = new byte[10];
        BinaryPrimitives.WriteUInt16LittleEndian(attrReqData, 4); // 4 attributes
        BinaryPrimitives.WriteUInt16LittleEndian(attrReqData.AsSpan(2), 1); // handle
        BinaryPrimitives.WriteUInt16LittleEndian(attrReqData.AsSpan(4), 2); // member count
        BinaryPrimitives.WriteUInt16LittleEndian(attrReqData.AsSpan(6), 4); // definition size
        BinaryPrimitives.WriteUInt16LittleEndian(attrReqData.AsSpan(8), 5); // structure size

        var attrData = await SendCipAsync(0x03, attrPath, attrReqData, ct);

        // Parse: count(2) + [attr_id(2) + status(2) + data]...
        int off = 2; // skip count
        ushort structHandle = 0;
        ushort memberCount = 0;
        uint definitionSize = 0;
        uint structureSize = 0;

        for (int i = 0; i < 4 && off + 4 <= attrData.Length; i++)
        {
            ushort attrId = BinaryPrimitives.ReadUInt16LittleEndian(attrData.AsSpan(off)); off += 2;
            ushort attrStatus = BinaryPrimitives.ReadUInt16LittleEndian(attrData.AsSpan(off)); off += 2;
            if (attrStatus != 0) continue;

            switch (attrId)
            {
                case 1: structHandle = BinaryPrimitives.ReadUInt16LittleEndian(attrData.AsSpan(off)); off += 2; break;
                case 2: memberCount = BinaryPrimitives.ReadUInt16LittleEndian(attrData.AsSpan(off)); off += 2; break;
                case 4: definitionSize = BinaryPrimitives.ReadUInt32LittleEndian(attrData.AsSpan(off)); off += 4; break;
                case 5: structureSize = BinaryPrimitives.ReadUInt32LittleEndian(attrData.AsSpan(off)); off += 4; break;
            }
        }

        // Step 2: Template Read (0x4C) — get member info + names
        // Read size = (definitionSize * 4) - 23
        int readSize = (int)(definitionSize * 4) - 23;
        if (readSize <= 0) readSize = 256;

        var members = new List<TemplateMemberDetail>();
        string templateName = "";

        // Read with fragmentation
        var allDefData = new List<byte>();
        uint readOffset = 0;

        while (true)
        {
            var readReqData = new byte[6];
            BinaryPrimitives.WriteUInt32LittleEndian(readReqData, readOffset);
            int remaining = readSize - (int)readOffset;
            BinaryPrimitives.WriteUInt16LittleEndian(readReqData.AsSpan(4), (ushort)Math.Min(remaining, ushort.MaxValue));

            var (readStatus, readData) = await SendCipWithStatusAsync(0x4C, attrPath, readReqData, ct);

            if (readStatus != 0x00 && readStatus != 0x06) break;
            allDefData.AddRange(readData);
            readOffset += (uint)readData.Length;

            if (readStatus == 0x00) break;
        }

        var defBytes = allDefData.ToArray();

        // Parse member info: memberCount * 8 bytes, then null-terminated names
        off = 0;
        for (int i = 0; i < memberCount && off + 8 <= defBytes.Length; i++)
        {
            uint typeAndInfo = BinaryPrimitives.ReadUInt32LittleEndian(defBytes.AsSpan(off)); off += 4;
            uint memberOffset = BinaryPrimitives.ReadUInt32LittleEndian(defBytes.AsSpan(off)); off += 4;

            ushort memberType = (ushort)(typeAndInfo >> 16);
            ushort memberInfo = (ushort)(typeAndInfo & 0xFFFF);

            members.Add(new TemplateMemberDetail
            {
                DataType = memberType,
                Info = memberInfo, // array size or bit position
                Offset = memberOffset,
            });
        }

        // Parse names: template name\0 then member names\0
        int nameStart = off;
        var names = new List<string>();
        while (off < defBytes.Length)
        {
            int end = Array.IndexOf(defBytes, (byte)0, off);
            if (end < 0) break;
            if (end > off)
                names.Add(Encoding.ASCII.GetString(defBytes, off, end - off));
            off = end + 1;
        }

        if (names.Count > 0) templateName = names[0];
        for (int i = 0; i < members.Count && i + 1 < names.Count; i++)
            members[i].Name = names[i + 1];

        return new TemplateInfo
        {
            InstanceId = templateInstanceId,
            Name = templateName,
            StructureHandle = structHandle,
            MemberCount = memberCount,
            DefinitionSize = definitionSize,
            StructureSize = structureSize,
            Members = members,
        };
    }

    /// <summary>Unregister session and close TCP connection.</summary>
    public async Task DisconnectAsync()
    {
        if (_stream != null && SessionHandle != 0)
        {
            try
            {
                var header = new EncapsulationHeader
                {
                    Command = EncapsulationCommand.UnregisterSession,
                    SessionHandle = SessionHandle,
                };
                var buf = new byte[EncapsulationHeader.Size];
                header.WriteTo(buf);
                await _stream.WriteAsync(buf);
            }
            catch { }
        }
        SessionHandle = 0;
        _stream?.Dispose();
        _client?.Dispose();
    }

    /// <summary>Dispose — disconnect if still connected.</summary>
    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync();
        _lock.Dispose();
    }

    // --- Private helpers ---

    /// <summary>
    /// Send a CIP service via Unconnected Send (0x52) to Connection Manager.
    /// Returns the response data (after MR response header).
    /// Throws on CIP error.
    /// </summary>
    private async Task<byte[]> SendCipAsync(byte serviceCode, byte[] cipPath, byte[] serviceData, CancellationToken ct)
    {
        var (status, data) = await SendCipWithStatusAsync(serviceCode, cipPath, serviceData, ct);
        if (status != 0x00 && status != 0x06)
            throw new InvalidOperationException($"CIP error: service=0x{serviceCode:X2}, status=0x{status:X2}");
        return data;
    }

    /// <summary>
    /// Send a CIP service and return (generalStatus, responseData).
    /// Sends directly as UCMM (no Unconnected Send wrapper) via SendRRData.
    /// </summary>
    private async Task<(byte status, byte[] data)> SendCipWithStatusAsync(
        byte serviceCode, byte[] cipPath, byte[] serviceData, CancellationToken ct)
    {
        // Build MR request: service + path_size_words + path + data
        int pathWords = cipPath.Length / 2;
        var mrRequest = new byte[2 + cipPath.Length + serviceData.Length];
        mrRequest[0] = serviceCode;
        mrRequest[1] = (byte)pathWords;
        cipPath.CopyTo(mrRequest.AsSpan(2));
        serviceData.CopyTo(mrRequest.AsSpan(2 + cipPath.Length));

        // Wrap in CPF: Null Address + Unconnected Data
        var cpfBuf = new byte[2048];
        int cpfLen = CpfParser.Write(cpfBuf, [
            new CpfItem { TypeId = CpfItemType.NullAddress, Data = ReadOnlyMemory<byte>.Empty },
            new CpfItem { TypeId = CpfItemType.UnconnectedData, Data = mrRequest },
        ]);

        // Build SendRRData payload: Interface Handle(4) + Timeout(2) + CPF
        var payload = new byte[6 + cpfLen];
        cpfBuf.AsSpan(0, cpfLen).CopyTo(payload.AsSpan(6));

        // Send and receive encapsulated
        var responsePayload = await SendEncapsulatedAsync(EncapsulationCommand.SendRRData, payload, ct);

        // Parse response CPF
        var responseCpf = CpfParser.Parse(responsePayload.AsSpan(6));
        foreach (var item in responseCpf)
        {
            if (item.TypeId == CpfItemType.UnconnectedData)
            {
                if (!MrCodec.TryParseResponse(item.Data, out _, out var cipStatus, out var respData))
                    throw new InvalidOperationException("Malformed CIP response");

                return (cipStatus.GeneralStatus, respData.ToArray());
            }
        }

        throw new InvalidOperationException("No response data");
    }

    private async Task<uint> RegisterSessionAsync(CancellationToken ct)
    {
        var payload = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(payload, 1); // protocol version
        var response = await SendEncapsulatedAsync(EncapsulationCommand.RegisterSession, payload, ct);
        return _lastHeader.SessionHandle;
    }

    private EncapsulationHeader _lastHeader;

    private async Task<byte[]> SendEncapsulatedAsync(EncapsulationCommand command, byte[] payload, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var header = new EncapsulationHeader
            {
                Command = command,
                Length = (ushort)payload.Length,
                SessionHandle = SessionHandle,
            };
            var buf = new byte[EncapsulationHeader.Size + payload.Length];
            header.WriteTo(buf);
            payload.CopyTo(buf.AsSpan(EncapsulationHeader.Size));
            await _stream!.WriteAsync(buf, ct);

            // Read response
            var respBuf = new byte[EncapsulationHeader.Size];
            await ReadExactAsync(respBuf, ct);
            _lastHeader = EncapsulationHeader.Parse(respBuf);

            if (_lastHeader.Status != EncapsulationStatus.Success)
                throw new InvalidOperationException($"Encapsulation error: {_lastHeader.Status}");

            var respPayload = Array.Empty<byte>();
            if (_lastHeader.Length > 0)
            {
                respPayload = new byte[_lastHeader.Length];
                await ReadExactAsync(respPayload, ct);
            }
            return respPayload;
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task ReadExactAsync(byte[] buffer, CancellationToken ct)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await _stream!.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) throw new IOException("Connection closed");
            read += n;
        }
    }

    /// <summary>
    /// Split a tag piece into (baseName, listOfIndexGroups). Each group is the
    /// comma-separated integer list inside one [...] pair. If a bracket can't
    /// be parsed as integers, it's left attached to the base name.
    /// </summary>
    private static (string BaseName, List<uint[]> BracketGroups) SplitBrackets(string piece)
    {
        var groups = new List<uint[]>();
        var baseName = piece;
        while (baseName.Length > 0 && baseName[^1] == ']')
        {
            int openIdx = baseName.LastIndexOf('[');
            if (openIdx < 0) break;
            var inside = baseName.Substring(openIdx + 1, baseName.Length - openIdx - 2);
            var indices = new List<uint>();
            bool ok = true;
            foreach (var raw in inside.Split(','))
            {
                var s = raw.Trim();
                if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    if (!uint.TryParse(s.AsSpan(2), System.Globalization.NumberStyles.HexNumber,
                                        System.Globalization.CultureInfo.InvariantCulture, out var hex))
                    { ok = false; break; }
                    indices.Add(hex);
                }
                else
                {
                    if (!uint.TryParse(s, out var dec)) { ok = false; break; }
                    indices.Add(dec);
                }
            }
            if (!ok) break;
            groups.Add(indices.ToArray());
            baseName = baseName.Substring(0, openIdx);
        }
        groups.Reverse();   // restore source order
        return (baseName, groups);
    }

    private static void EmitSymbolic(List<byte> dst, string part)
    {
        var b = Encoding.ASCII.GetBytes(part);
        dst.Add(0x91);
        dst.Add((byte)b.Length);
        dst.AddRange(b);
        if (b.Length % 2 != 0) dst.Add(0);
    }

    private static void EmitElement(List<byte> dst, uint v)
    {
        if (v <= 0xFF) { dst.Add(0x28); dst.Add((byte)v); }
        else if (v <= 0xFFFF)
        {
            dst.Add(0x29); dst.Add(0x00);
            dst.Add((byte)(v & 0xFF));
            dst.Add((byte)((v >> 8) & 0xFF));
        }
        else
        {
            dst.Add(0x2A); dst.Add(0x00);
            dst.Add((byte)(v & 0xFF));
            dst.Add((byte)((v >> 8) & 0xFF));
            dst.Add((byte)((v >> 16) & 0xFF));
            dst.Add((byte)((v >> 24) & 0xFF));
        }
    }

    private static void EmitSymbolInstance(List<byte> dst, uint inst)
    {
        // Logical: Class 0x6B (Symbol Object) + 16-bit Instance.
        dst.Add(0x20); dst.Add(0x6B);
        dst.Add(0x25); dst.Add(0x00);
        dst.Add((byte)(inst & 0xFF));
        dst.Add((byte)((inst >> 8) & 0xFF));
    }

    /// <summary>
    /// Build a Logix tag path with ANSI symbolic segments and element segments.
    /// No instance-ID lookup — this is the all-symbolic fallback used when the
    /// instance cache is empty or the tag isn't in it.
    /// </summary>
    private static byte[] BuildSymbolicPath(string name)
    {
        var dst = new List<byte>(name.Length + 8);
        foreach (var piece in name.Split('.'))
        {
            var (baseName, groups) = SplitBrackets(piece);
            if (baseName.Length > 0) EmitSymbolic(dst, baseName);
            foreach (var grp in groups)
                foreach (var idx in grp)
                    EmitElement(dst, idx);
        }
        return dst.ToArray();
    }

    /// <summary>
    /// Cache-aware Logix tag path builder. When the root tag is in the
    /// instance-ID cache, emits a 6-byte logical Symbol Object segment
    /// (Class 0x6B + 16-bit Instance) instead of the longer ANSI symbolic
    /// segment. Logix rejects INST for the "Program:Foo" prefix piece itself
    /// — that stays symbolic on the wire — but accepts INST for the
    /// in-program tag root.
    /// </summary>
    private byte[] BuildTagPath(string name)
    {
        var parts = name.Split('.');
        var headPart = parts[0];
        var (headBase, headBrackets) = SplitBrackets(headPart);

        // (2) Program-scope drilling.
        if (headBase.StartsWith("Program:") && parts.Length >= 2)
        {
            var leafPart = parts[1];
            var (leafBase, leafBrackets) = SplitBrackets(leafPart);
            if (_programAtoms.TryGetValue((headBase, leafBase), out var inst))
            {
                var dst = new List<byte>(name.Length + 8);
                EmitSymbolic(dst, headBase);
                foreach (var grp in headBrackets)
                    foreach (var idx in grp) EmitElement(dst, idx);
                EmitSymbolInstance(dst, inst);
                foreach (var grp in leafBrackets)
                    foreach (var idx in grp) EmitElement(dst, idx);
                for (int i = 2; i < parts.Length; i++)
                {
                    var (pb, pi) = SplitBrackets(parts[i]);
                    if (pb.Length > 0) EmitSymbolic(dst, pb);
                    foreach (var grp in pi)
                        foreach (var idx in grp) EmitElement(dst, idx);
                }
                return dst.ToArray();
            }
            // Leaf not in cache — fall back to all-symbolic.
            return BuildSymbolicPath(name);
        }

        // (1) Controller-scope root.
        if (_controllerAtoms.TryGetValue(headBase, out var rootInst))
        {
            var dst = new List<byte>(name.Length + 8);
            EmitSymbolInstance(dst, rootInst);
            foreach (var grp in headBrackets)
                foreach (var idx in grp) EmitElement(dst, idx);
            for (int i = 1; i < parts.Length; i++)
            {
                var (pb, pi) = SplitBrackets(parts[i]);
                if (pb.Length > 0) EmitSymbolic(dst, pb);
                foreach (var grp in pi)
                    foreach (var idx in grp) EmitElement(dst, idx);
            }
            return dst.ToArray();
        }

        // (3) Cache miss.
        return BuildSymbolicPath(name);
    }

    /// <summary>Map a .NET type to the corresponding Logix tag type code.</summary>
    private static ushort GuessTagType<T>() where T : unmanaged
    {
        if (typeof(T) == typeof(bool)) return LogixDataTypes.BOOL;
        if (typeof(T) == typeof(int) || typeof(T) == typeof(uint)) return LogixDataTypes.DINT;
        if (typeof(T) == typeof(float)) return LogixDataTypes.REAL;
        if (typeof(T) == typeof(short) || typeof(T) == typeof(ushort)) return LogixDataTypes.INT;
        if (typeof(T) == typeof(sbyte) || typeof(T) == typeof(byte)) return LogixDataTypes.SINT;
        if (typeof(T) == typeof(long) || typeof(T) == typeof(ulong)) return LogixDataTypes.LINT;
        if (typeof(T) == typeof(double)) return LogixDataTypes.LREAL;
        throw new NotSupportedException($"Cannot map {typeof(T).Name} to a Logix tag type");
    }
}

/// <summary>Result of BrowseTagsAsync — all tags and their resolved templates.</summary>
public sealed class TagBrowseResult
{
    /// <summary>All tags found in the controller.</summary>
    public List<TagInfo> Tags { get; init; } = [];

    /// <summary>All structure templates, keyed by template instance ID.</summary>
    public Dictionary<ushort, TemplateInfo> Templates { get; init; } = [];

    /// <summary>User tags only (excludes system tags and __ prefixed).</summary>
    public IEnumerable<TagInfo> UserTags => Tags.Where(t => !t.IsSystem && !t.Name.StartsWith("__"));
}

/// <summary>Information about a single tag from the Symbol Object.</summary>
public sealed class TagInfo
{
    /// <summary>Tag name as it appears in the controller. Prefixed with program name for program-scope tags.</summary>
    public string Name { get; set; } = "";

    /// <summary>Symbol Object instance ID.</summary>
    public uint InstanceId { get; init; }

    /// <summary>Raw SymbolType attribute value.</summary>
    public ushort SymbolType { get; init; }

    /// <summary>True if this is a structured data type.</summary>
    public bool IsStruct { get; init; }

    /// <summary>True if this is a system tag (bit 12 set).</summary>
    public bool IsSystem { get; init; }

    /// <summary>Array dimensions (0-3).</summary>
    public int ArrayDimensions { get; init; }

    /// <summary>For atomic: CIP type code. For struct: template instance ID.</summary>
    public ushort TypeCode { get; init; }

    /// <summary>Resolved template (null if atomic or template not found).</summary>
    public TemplateInfo? Template { get; set; }

    public override string ToString() =>
        IsStruct ? $"{Name} (struct: {Template?.Name ?? $"template #{TypeCode}"})" : $"{Name} (0x{TypeCode:X4})";
}

/// <summary>Structure template definition read from Template Object (class 0x6C).</summary>
public sealed class TemplateInfo
{
    /// <summary>Template Object instance ID.</summary>
    public ushort InstanceId { get; init; }

    /// <summary>Structure/UDT name.</summary>
    public string Name { get; init; } = "";

    /// <summary>Structure handle used as tag type parameter in Read/Write Tag.</summary>
    public ushort StructureHandle { get; init; }

    /// <summary>Number of members.</summary>
    public ushort MemberCount { get; init; }

    /// <summary>Template definition size in 32-bit words.</summary>
    public uint DefinitionSize { get; init; }

    /// <summary>Structure size in bytes when read/written on the wire.</summary>
    public uint StructureSize { get; init; }

    /// <summary>Member definitions with types, offsets, and names.</summary>
    public List<TemplateMemberDetail> Members { get; init; } = [];

    public override string ToString() => $"{Name} ({MemberCount} members, {StructureSize} bytes)";
}

/// <summary>A single member within a structure template.</summary>
public sealed class TemplateMemberDetail
{
    /// <summary>Member name.</summary>
    public string Name { get; set; } = "";

    /// <summary>CIP data type code (upper 16 bits of the type_and_info field).</summary>
    public ushort DataType { get; init; }

    /// <summary>Info field: array size for arrays, bit position for BOOLs, 0 for scalars.</summary>
    public ushort Info { get; init; }

    /// <summary>Byte offset of this member within the structure.</summary>
    public uint Offset { get; init; }

    /// <summary>True if this member is an array (Info > 0 and not a BOOL bit).</summary>
    public bool IsArray => Info > 0 && DataType != 0x00C1;

    /// <summary>Array size (0 for scalars).</summary>
    public int ArraySize => IsArray ? Info : 0;

    public override string ToString()
    {
        string type = $"0x{DataType:X4}";
        string arr = IsArray ? $"[{ArraySize}]" : "";
        return $"{Name}: {type}{arr} @ offset {Offset}";
    }
}

/// <summary>
/// A read/write structure value — provides named access to individual members
/// from a raw structure byte blob using the template definition.
/// Use for reading: populate via constructor with data from PLC.
/// Use for writing: create empty, set members, call ToBytes().
/// </summary>
public sealed class StructureValue
{
    /// <summary>The template that describes this structure's layout.</summary>
    public TemplateInfo Template { get; }

    /// <summary>Raw structure data bytes (mutable — writes modify this directly).</summary>
    public byte[] RawData { get; }

    /// <summary>Create from PLC data (for reading).</summary>
    public StructureValue(TemplateInfo template, byte[] rawData)
    {
        Template = template;
        RawData = rawData;
    }

    /// <summary>Create an empty structure (for writing). Allocates a zeroed buffer.</summary>
    public StructureValue(TemplateInfo template)
    {
        Template = template;
        RawData = new byte[template.StructureSize];
    }

    /// <summary>Get the raw bytes for writing to the PLC.</summary>
    public byte[] ToBytes() => RawData;

    /// <summary>Get a member by name. Returns null if not found.</summary>
    public TemplateMemberDetail? GetMember(string name) =>
        Template.Members.FirstOrDefault(m => m.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Read a typed value from a named member.</summary>
    public T Get<T>(string memberName) where T : unmanaged
    {
        var member = GetMember(memberName)
            ?? throw new KeyNotFoundException($"Member '{memberName}' not found in {Template.Name}");

        if (member.Offset + System.Runtime.CompilerServices.Unsafe.SizeOf<T>() > RawData.Length)
            throw new InvalidOperationException($"Member '{memberName}' at offset {member.Offset} exceeds data length {RawData.Length}");

        return System.Runtime.CompilerServices.Unsafe.ReadUnaligned<T>(ref RawData[(int)member.Offset]);
    }

    /// <summary>Read a BOOL member (bit within a SINT host byte).</summary>
    public bool GetBool(string memberName)
    {
        var member = GetMember(memberName)
            ?? throw new KeyNotFoundException($"Member '{memberName}' not found in {Template.Name}");

        if (member.DataType != 0x00C1)
            throw new InvalidOperationException($"Member '{memberName}' is not BOOL (type=0x{member.DataType:X4})");

        byte hostByte = RawData[(int)member.Offset];
        int bitPosition = member.Info; // Info field holds the bit position for BOOLs
        return (hostByte & (1 << bitPosition)) != 0;
    }

    /// <summary>Read a STRING member (Logix STRING structure nested at the given offset).</summary>
    public string GetString(string memberName)
    {
        var member = GetMember(memberName)
            ?? throw new KeyNotFoundException($"Member '{memberName}' not found in {Template.Name}");

        int off = (int)member.Offset;
        if (off + LogixDataTypes.StringDataOffset >= RawData.Length) return "";

        int len = BinaryPrimitives.ReadInt32LittleEndian(RawData.AsSpan(off));
        if (len <= 0) return "";

        int maxLen = Math.Min(len, Math.Min(LogixDataTypes.StringMaxLength, RawData.Length - off - LogixDataTypes.StringDataOffset));
        return Encoding.ASCII.GetString(RawData, off + LogixDataTypes.StringDataOffset, maxLen);
    }

    /// <summary>Read an array member and return it as a typed array.</summary>
    public T[] GetArray<T>(string memberName) where T : unmanaged
    {
        var member = GetMember(memberName)
            ?? throw new KeyNotFoundException($"Member '{memberName}' not found in {Template.Name}");

        if (!member.IsArray)
            throw new InvalidOperationException($"Member '{memberName}' is not an array");

        int elemSize;
        unsafe { elemSize = sizeof(T); }
        int count = member.ArraySize;
        var result = new T[count];
        int off = (int)member.Offset;

        for (int i = 0; i < count && off + elemSize <= RawData.Length; i++)
        {
            result[i] = System.Runtime.CompilerServices.Unsafe.ReadUnaligned<T>(ref RawData[off]);
            off += elemSize;
        }
        return result;
    }

    // --- Writers ---

    /// <summary>Write a typed value to a named member.</summary>
    public void Set<T>(string memberName, T value) where T : unmanaged
    {
        var member = GetMember(memberName)
            ?? throw new KeyNotFoundException($"Member '{memberName}' not found in {Template.Name}");

        System.Runtime.CompilerServices.Unsafe.WriteUnaligned(ref RawData[(int)member.Offset], value);
    }

    /// <summary>Write a BOOL member (set/clear a bit within the SINT host byte).</summary>
    public void SetBool(string memberName, bool value)
    {
        var member = GetMember(memberName)
            ?? throw new KeyNotFoundException($"Member '{memberName}' not found in {Template.Name}");

        if (member.DataType != 0x00C1)
            throw new InvalidOperationException($"Member '{memberName}' is not BOOL");

        int off = (int)member.Offset;
        int bit = member.Info;
        if (value)
            RawData[off] |= (byte)(1 << bit);
        else
            RawData[off] &= (byte)~(1 << bit);
    }

    /// <summary>Write a STRING member (Logix STRING structure at the given offset).</summary>
    public void SetString(string memberName, string value)
    {
        var member = GetMember(memberName)
            ?? throw new KeyNotFoundException($"Member '{memberName}' not found in {Template.Name}");

        int off = (int)member.Offset;
        var strBytes = Encoding.ASCII.GetBytes(value);
        int len = Math.Min(strBytes.Length, LogixDataTypes.StringMaxLength);
        BinaryPrimitives.WriteInt32LittleEndian(RawData.AsSpan(off), len);
        RawData.AsSpan(off + LogixDataTypes.StringDataOffset, LogixDataTypes.StringMaxLength).Clear();
        strBytes.AsSpan(0, len).CopyTo(RawData.AsSpan(off + LogixDataTypes.StringDataOffset));
    }

    /// <summary>Write an array of typed values to a named member.</summary>
    public void SetArray<T>(string memberName, T[] values) where T : unmanaged
    {
        var member = GetMember(memberName)
            ?? throw new KeyNotFoundException($"Member '{memberName}' not found in {Template.Name}");

        int elemSize;
        unsafe { elemSize = sizeof(T); }
        int off = (int)member.Offset;
        int count = Math.Min(values.Length, member.IsArray ? member.ArraySize : values.Length);

        for (int i = 0; i < count && off + elemSize <= RawData.Length; i++)
        {
            System.Runtime.CompilerServices.Unsafe.WriteUnaligned(ref RawData[off], values[i]);
            off += elemSize;
        }
    }

    /// <summary>Get all non-hidden members as a dictionary of name → formatted value string.</summary>
    public Dictionary<string, string> ToDictionary()
    {
        var result = new Dictionary<string, string>();
        foreach (var m in Template.Members)
        {
            // Skip hidden host bytes (ZZZZZZZZZZ prefix)
            if (m.Name.StartsWith("ZZZZZZZZZZ") || m.Name.StartsWith("__") || string.IsNullOrEmpty(m.Name))
                continue;

            try
            {
                string value = FormatMember(m);
                result[m.Name] = value;
            }
            catch
            {
                result[m.Name] = "?";
            }
        }
        return result;
    }

    private string FormatMember(TemplateMemberDetail m)
    {
        int off = (int)m.Offset;
        if (off >= RawData.Length) return "?";

        // BOOL — bit within host byte
        if (m.DataType == 0x00C1)
        {
            byte host = RawData[off];
            bool val = (host & (1 << m.Info)) != 0;
            return val ? "True" : "False";
        }

        // Atomic types
        ushort baseType = (ushort)(m.DataType & 0x00FF);
        if (!m.IsArray && (m.DataType & 0xFF00) == 0)
        {
            return baseType switch
            {
                0xC2 => ((sbyte)RawData[off]).ToString(),
                0xC3 => BinaryPrimitives.ReadInt16LittleEndian(RawData.AsSpan(off)).ToString(),
                0xC4 => BinaryPrimitives.ReadInt32LittleEndian(RawData.AsSpan(off)).ToString(),
                0xC5 => BinaryPrimitives.ReadInt64LittleEndian(RawData.AsSpan(off)).ToString(),
                0xCA => BinaryPrimitives.ReadSingleLittleEndian(RawData.AsSpan(off)).ToString("G"),
                0xCB => BinaryPrimitives.ReadDoubleLittleEndian(RawData.AsSpan(off)).ToString("G"),
                _ => $"0x{baseType:X2}@{off}",
            };
        }

        // Array of atomics
        if (m.IsArray && (m.DataType & 0xE000) == 0x2000)
        {
            int count = Math.Min(m.ArraySize, 4); // Show first 4
            var vals = new List<string>();
            int elemSize = LogixDataTypes.GetElementSize((ushort)(m.DataType & 0x00FF));
            if (elemSize <= 0) return $"[{m.ArraySize}]";
            for (int i = 0; i < count && off + elemSize <= RawData.Length; i++)
            {
                int v = elemSize switch
                {
                    1 => RawData[off],
                    2 => BinaryPrimitives.ReadInt16LittleEndian(RawData.AsSpan(off)),
                    4 => BinaryPrimitives.ReadInt32LittleEndian(RawData.AsSpan(off)),
                    _ => 0,
                };
                vals.Add(v.ToString());
                off += elemSize;
            }
            string suffix = m.ArraySize > 4 ? ", ..." : "";
            return $"[{string.Join(", ", vals)}{suffix}]";
        }

        // Nested struct — show as [struct@offset]
        if ((m.DataType & 0x8000) != 0)
            return $"[struct@{off}]";

        return $"0x{m.DataType:X4}@{off}";
    }
}
