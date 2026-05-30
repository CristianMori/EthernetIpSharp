using System.Buffers.Binary;
using EthernetIPSharp.Connections;

namespace EthernetIPSharp.Safety;

/// <summary>
/// Connection Parameter CRC (CPCRC) — CRC-S4 computed over Forward Open fields.
/// Used by both originator (to build SafetyOpen) and target (to validate).
///
/// The CPCRC covers (in order):
///   Connection Serial Number, Originator Vendor ID, Originator Serial Number,
///   Connection Timeout Multiplier, O→T RPI, O→T Network Connection Parameters,
///   T→O RPI, T→O Network Connection Parameters, Transport Type/Trigger,
///   Connection Path Size (adjusted), Connection Path (without safety/routing segments),
///   Safety segment fields (SCCRC, SCTS, timing params, TUNID, OUNID, etc.)
/// </summary>
public static class SafetyCpcrc
{
    /// <summary>
    /// Compute the CPCRC from Forward Open parameters and safety network segment fields.
    /// </summary>
    public static uint Compute(
        ushort connectionSerialNumber,
        ushort originatorVendorId,
        uint originatorSerialNumber,
        byte connectionTimeoutMultiplier,
        uint otoTRpi,
        ushort otoTNetworkParams,
        uint ttoORpi,
        ushort ttoONetworkParams,
        byte transportClassTrigger,
        byte connectionPathSizeWords,
        ReadOnlySpan<byte> connectionPath,
        SafetyNetworkSegment safetySegment)
    {
        // Build the data to CRC in order
        // Estimate max size: fixed fields + path + safety segment fields
        var buf = new byte[256 + connectionPath.Length];
        int off = 0;

        // Connection triad
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(off), connectionSerialNumber); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(off), originatorVendorId); off += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off), originatorSerialNumber); off += 4;

        // Connection timeout multiplier
        buf[off++] = connectionTimeoutMultiplier;

        // O→T RPI + params
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off), otoTRpi); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(off), otoTNetworkParams); off += 2;

        // T→O RPI + params
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off), ttoORpi); off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(off), ttoONetworkParams); off += 2;

        // Transport type/trigger
        buf[off++] = transportClassTrigger;

        // Connection path size (in words) — pre-adjusted to exclude routing segments
        buf[off++] = connectionPathSizeWords;

        // Connection path (application path only, no routing or safety segments)
        connectionPath.CopyTo(buf.AsSpan(off)); off += connectionPath.Length;

        // Safety segment fields covered by CPCRC (everything except the CPCRC itself)
        // SCCRC
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off), safetySegment.Sccrc); off += 4;
        // SCTS
        (safetySegment.Scts ?? new byte[6]).CopyTo(buf.AsSpan(off)); off += 6;
        // Time Correction EPI
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off), safetySegment.TimeCorrectionEpi); off += 4;
        // Time Correction Network Connection Parameters
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(off), safetySegment.TimeCorrectionParams); off += 2;
        // TUNID
        safetySegment.Tunid.CopyTo(buf.AsSpan(off)); off += UniqueNetworkId.Size;
        // OUNID
        safetySegment.Ounid.CopyTo(buf.AsSpan(off)); off += UniqueNetworkId.Size;
        // Ping interval, time coord, NTE multipliers
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(off), safetySegment.PingIntervalMultiplier); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(off), safetySegment.TimeCoordMsgMinMultiplier); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(off), safetySegment.NetworkTimeExpectationMultiplier); off += 2;
        // Timeout multiplier + max consumer
        buf[off++] = safetySegment.TimeoutMultiplier;
        buf[off++] = safetySegment.MaxConsumerNumber;
        // Time Correction Connection ID
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off), safetySegment.TimeCorrectionConnectionId); off += 4;

        return SafetyCrc.ComputeS4(buf.AsSpan(0, off));
    }

    /// <summary>
    /// Compute CPCRC from a parsed ForwardOpenRequest and safety segment.
    /// Convenience overload that extracts fields from the request.
    /// </summary>
    public static uint Compute(ForwardOpenRequest request, SafetyNetworkSegment safetySegment,
        ReadOnlySpan<byte> applicationPath)
    {
        // Reconstruct network params as raw UINT for CRC
        ushort otParams = EncodeNetworkParams(request.OtoTParams);
        ushort toParams = EncodeNetworkParams(request.TtoOParams);

        return Compute(
            request.ConnectionSerialNumber,
            request.OriginatorVendorId,
            request.OriginatorSerialNumber,
            request.ConnectionTimeoutMultiplier,
            request.OtoTRpi,
            otParams,
            request.TtoORpi,
            toParams,
            request.TransportClassTrigger,
            (byte)(applicationPath.Length / 2),
            applicationPath,
            safetySegment);
    }

    /// <summary>Re-encode NetworkConnectionParams back to raw 16-bit wire format.</summary>
    private static ushort EncodeNetworkParams(NetworkConnectionParams p)
    {
        ushort raw = 0;
        if (p.RedundantOwner) raw |= 0x8000;
        raw |= (ushort)((p.ConnectionType & 0x03) << 13);
        raw |= (ushort)((p.Priority & 0x03) << 10);
        if (p.IsVariable) raw |= 0x0200;
        raw |= (ushort)(p.ConnectionSize & 0x01FF);
        return raw;
    }
}
