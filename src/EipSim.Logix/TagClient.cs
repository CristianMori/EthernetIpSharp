using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using EipSim.Cip;

namespace EipSim.Logix;

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

    /// <summary>Read a tag and return the raw response (tag_type + data bytes).</summary>
    public async Task<byte[]> ReadTagRawAsync(string tagName, ushort elementCount = 1, CancellationToken ct = default)
    {
        var path = BuildSymbolicPath(tagName);
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

        var path = BuildSymbolicPath(tagName);
        await SendCipAsync(TagServices.WriteTag, path, data, ct);
    }

    /// <summary>Write raw data to a tag with explicit tag type and element count.</summary>
    public async Task WriteRawAsync(string tagName, ushort tagType, ushort elementCount, byte[] value, CancellationToken ct = default)
    {
        var data = new byte[4 + value.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(data, tagType);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2), elementCount);
        value.CopyTo(data.AsSpan(4));

        var path = BuildSymbolicPath(tagName);
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

        // Step 2: Find programs and browse their tags
        var programs = tags
            .Where(t => t.Name.StartsWith("Program:") && !t.Name.Contains('.'))
            .Select(t => t.Name)
            .ToList();

        foreach (var program in programs)
        {
            var programTags = await BrowseSymbolsAsync(program, ct);
            // Prefix program-scope tag names with the program name
            foreach (var t in programTags)
                t.Name = $"{program}.{t.Name}";
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
        // Read size = (definitionSize * 4) - 23 per spec
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

    /// <summary>Build ANSI Extended Symbolic Segment path bytes for a tag name.</summary>
    private static byte[] BuildSymbolicPath(string name)
    {
        var nameBytes = Encoding.ASCII.GetBytes(name);
        int padded = nameBytes.Length % 2 != 0 ? nameBytes.Length + 1 : nameBytes.Length;
        var path = new byte[2 + padded];
        path[0] = 0x91;
        path[1] = (byte)nameBytes.Length;
        nameBytes.CopyTo(path, 2);
        return path;
    }

    /// <summary>Map a .NET type to the corresponding Logix tag type code.</summary>
    private static ushort GuessTagType<T>() where T : unmanaged
    {
        if (typeof(T) == typeof(int) || typeof(T) == typeof(uint)) return LogixDataTypes.DINT;
        if (typeof(T) == typeof(float)) return LogixDataTypes.REAL;
        if (typeof(T) == typeof(short) || typeof(T) == typeof(ushort)) return LogixDataTypes.INT;
        if (typeof(T) == typeof(sbyte) || typeof(T) == typeof(byte)) return LogixDataTypes.SINT;
        if (typeof(T) == typeof(long) || typeof(T) == typeof(ulong)) return LogixDataTypes.LINT;
        if (typeof(T) == typeof(double)) return 0x00CB; // LREAL
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
