using System.Buffers;
using System.Buffers.Binary;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Logix;

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

    /// <summary>
    /// Nested re-entry into the dispatcher (0x0A inside 0x0A, 0x0A inside 0x52,
    /// or the reverse) is capped through <see cref="CipDispatchDepth"/>. The
    /// counter is shared with <see cref="EthernetIPSharp.Connections.ConnectionManagerObject"/>
    /// so a mixed 0x52 ⇒ 0x0A ⇒ 0x52 ⇒ 0x0A chain cannot defeat the cap by
    /// alternating service codes. Without a cap, a crafted packet that lists
    /// itself as its own sub-request recurses unboundedly and raises
    /// <see cref="StackOverflowException"/>, which .NET cannot catch — it
    /// tears down the host process.
    /// </summary>
    public static CipServiceResponse Handle(ICipDispatch dispatch, CipServiceRequest request)
    {
        if (CipDispatchDepth.AtLimit)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.ServiceNotSupported));

        CipDispatchDepth.Enter();
        try
        {
            return HandleInner(dispatch, request);
        }
        finally
        {
            CipDispatchDepth.Exit();
        }
    }

    private static CipServiceResponse HandleInner(ICipDispatch dispatch, CipServiceRequest request)
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

        // Validate the full offset table BEFORE dispatching anything. Offsets must
        // be monotonically non-decreasing, must start at or after the offset table
        // itself, and must stay within the request body. If we discovered a bad
        // offset mid-batch, earlier sub-requests would have already executed
        // (writes committed) before the handler threw on a bad Slice — a partial
        // commit the caller has no way to roll back.
        for (int i = 0; i < serviceCount; i++)
        {
            if (offsets[i] < headerSize || offsets[i] > request.Data.Length)
                return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));
            if (i > 0 && offsets[i] < offsets[i - 1])
                return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(0x13));
        }

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
