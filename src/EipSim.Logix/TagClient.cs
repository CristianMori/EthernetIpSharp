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
    /// Browse all tags by iterating Get_Instance_Attribute_List on Symbol class 0x6B.
    /// Returns a list of (name, symbolType) pairs.
    /// </summary>
    public async Task<List<(string Name, ushort SymbolType)>> BrowseTagsAsync(CancellationToken ct = default)
    {
        var result = new List<(string, ushort)>();
        uint startInstance = 0;

        while (true)
        {
            var path = new byte[6];
            path[0] = 0x20; path[1] = 0x6B; // Class 0x6B (Symbol)
            path[2] = 0x25; path[3] = 0x00; // 16-bit instance
            BinaryPrimitives.WriteUInt16LittleEndian(path.AsSpan(4), (ushort)startInstance);

            var reqData = new byte[6];
            BinaryPrimitives.WriteUInt16LittleEndian(reqData, 2);       // 2 attributes
            BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(2), 1); // attr 1 (name)
            BinaryPrimitives.WriteUInt16LittleEndian(reqData.AsSpan(4), 2); // attr 2 (type)

            var (status, data) = await SendCipWithStatusAsync(0x55, path, reqData, ct);

            if (status != 0x00 && status != 0x06)
                break; // Error other than "more data"

            // Parse entries: [instance_id(4) + name_len(2) + name + symbol_type(2)]...
            int off = 0;
            while (off + 6 < data.Length)
            {
                uint instId = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(off)); off += 4;
                ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;
                if (off + nameLen + 2 > data.Length) break;
                string name = Encoding.ASCII.GetString(data, off, nameLen); off += nameLen;
                ushort symType = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off)); off += 2;

                result.Add((name, symType));
                startInstance = instId;
            }

            if (status == 0x00) break; // All done
            startInstance++;
        }

        return result;
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
