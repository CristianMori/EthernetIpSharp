using System.Buffers.Binary;
using EipSim.Cip;

namespace EipSim.Logix;

/// <summary>
/// Multiple Service Packet Service (0x0A).
/// Combines multiple CIP requests into a single message frame.
/// Routed to Message Router (Class 0x02, Instance 1).
///
/// Request: service_count (UINT) + offsets[service_count] (UINT each) + packed MR requests
/// Response: service_count (UINT) + offsets[service_count] (UINT each) + packed MR responses
/// </summary>
public static class MultiServiceHandler
{
    public const byte ServiceCode = 0x0A;

    public static CipServiceResponse Handle(ICipDispatch dispatch, CipServiceRequest request)
    {
        if (request.Data.Length < 2)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));

        var span = request.Data.Span;
        ushort serviceCount = BinaryPrimitives.ReadUInt16LittleEndian(span);

        int headerSize = 2 + serviceCount * 2; // count + offset table
        if (request.Data.Length < headerSize)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));

        // Read offsets (relative to start of Request Data, i.e. after the MR request header)
        var offsets = new ushort[serviceCount];
        for (int i = 0; i < serviceCount; i++)
            offsets[i] = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2 + i * 2));

        // Dispatch each sub-request and collect responses
        var responses = new byte[serviceCount][];
        for (int i = 0; i < serviceCount; i++)
        {
            int subStart = offsets[i];
            int subEnd = i + 1 < serviceCount ? offsets[i + 1] : request.Data.Length;
            var subRequestData = request.Data.Slice(subStart, subEnd - subStart);

            // Parse sub-request as MR format: service + path_size + path + data
            var (svcCode, path, svcData) = MrCodec.ParseRequest(subRequestData);

            // Dispatch through the full CIP dispatch chain
            var subResponse = dispatch.Dispatch(svcCode, path, svcData);

            // Encode the MR response
            var respBuf = new byte[4096];
            int respLen = subResponse.Encode(respBuf);
            responses[i] = respBuf.AsSpan(0, respLen).ToArray();
        }

        // Build the aggregate response
        // Format: service_count (UINT) + offsets[] + packed responses
        int respHeaderSize = 2 + serviceCount * 2;
        int totalRespSize = respHeaderSize;
        foreach (var r in responses)
            totalRespSize += r.Length;

        var result = new byte[totalRespSize];
        int offset = 0;

        // Service count
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(offset), serviceCount);
        offset += 2;

        // Calculate and write response offsets
        int dataStart = respHeaderSize;
        int currentOffset = dataStart;
        for (int i = 0; i < serviceCount; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(offset), (ushort)currentOffset);
            offset += 2;
            currentOffset += responses[i].Length;
        }

        // Write packed responses
        foreach (var r in responses)
        {
            r.CopyTo(result.AsSpan(offset));
            offset += r.Length;
        }

        return CipServiceResponse.Success(request.ServiceCode, result);
    }
}
