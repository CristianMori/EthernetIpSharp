using System.Buffers;
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

    /// <summary>Max encoded size of a single CIP service response (header + data).</summary>
    private const int MaxSingleResponseSize = 520;

    public static CipServiceResponse Handle(ICipDispatch dispatch, CipServiceRequest request)
    {
        if (request.Data.Length < 2)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));

        var span = request.Data.Span;
        ushort serviceCount = BinaryPrimitives.ReadUInt16LittleEndian(span);

        int headerSize = 2 + serviceCount * 2;
        if (request.Data.Length < headerSize)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));

        // Read offsets
        var offsets = new ushort[serviceCount];
        for (int i = 0; i < serviceCount; i++)
            offsets[i] = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2 + i * 2));

        // Encode each sub-response into a shared buffer to avoid per-response 4KB allocations
        var encodeBuf = ArrayPool<byte>.Shared.Rent(MaxSingleResponseSize);
        try
        {
            // Collect encoded responses — each is an exact-sized byte[]
            var responses = new byte[serviceCount][];
            for (int i = 0; i < serviceCount; i++)
            {
                int subStart = offsets[i];
                int subEnd = i + 1 < serviceCount ? offsets[i + 1] : request.Data.Length;
                var subRequestData = request.Data.Slice(subStart, subEnd - subStart);

                var (svcCode, path, svcData) = MrCodec.ParseRequest(subRequestData);
                var subResponse = dispatch.Dispatch(svcCode, path, svcData);

                int respLen = subResponse.Encode(encodeBuf);
                responses[i] = encodeBuf.AsSpan(0, respLen).ToArray();
            }

            // Build aggregate response
            int respHeaderSize = 2 + serviceCount * 2;
            int totalRespSize = respHeaderSize;
            foreach (var r in responses)
                totalRespSize += r.Length;

            var result = new byte[totalRespSize];
            int offset = 0;

            BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(offset), serviceCount);
            offset += 2;

            int currentOffset = respHeaderSize;
            for (int i = 0; i < serviceCount; i++)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(offset), (ushort)currentOffset);
                offset += 2;
                currentOffset += responses[i].Length;
            }

            foreach (var r in responses)
            {
                r.CopyTo(result.AsSpan(offset));
                offset += r.Length;
            }

            return CipServiceResponse.Success(request.ServiceCode, result);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(encodeBuf);
        }
    }
}
