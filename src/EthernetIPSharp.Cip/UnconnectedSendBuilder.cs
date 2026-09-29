using System.Buffers.Binary;

namespace EthernetIPSharp.Cip;

/// <summary>
/// Builds the wire bytes for an Unconnected_Send (service 0x52) message routed
/// through the Connection Manager (class 0x06, instance 1).  Used by scanners
/// that need to reach a device via a backplane route path — for example
/// path <c>1,N</c> to talk to a ControlLogix CPU in slot N through its 1756-EN
/// module.
///
/// Wire layout (from CIP Vol 1 §3-5.5.4):
/// <code>
///   USINT priority_and_tick_time
///   USINT timeout_ticks
///   UINT  embedded_message_size
///   BYTES embedded_message
///   BYTE  pad if embedded_message_size is odd
///   USINT route_path_size_words
///   USINT reserved (0)
///   BYTES route_path
/// </code>
/// The outer MR wraps this as service 0x52 with path
/// <c>0x20 0x06 0x24 0x01</c> (Connection Manager instance 1).
/// </summary>
public static class UnconnectedSendBuilder
{
    private const byte ServiceCode = 0x52;
    private const byte DefaultPriorityTick = 0x07; // priority 0, time-tick 7 (~ms granularity)
    private const byte DefaultTimeoutTicks = 0xF9; // 249 * 2^7 ms ≈ 31.9 s
    private static readonly byte[] ConnectionManagerPath = { 0x20, 0x06, 0x24, 0x01 };

    /// <summary>
    /// Wrap an embedded MR (service + path_size + path + service data) into an
    /// Unconnected_Send MR ready to hand to <c>SendRRData</c>.  Returns the
    /// outer MR bytes.
    /// </summary>
    /// <param name="innerMr">The already-encoded inner message-router request.</param>
    /// <param name="routePath">Backplane route bytes (e.g. <c>{0x01, 0x00}</c> for slot 0).</param>
    public static byte[] Wrap(byte[] innerMr, byte[] routePath)
    {
        if (routePath.Length == 0)
            throw new ArgumentException("Route path must not be empty; caller should send bare MR instead", nameof(routePath));
        if (routePath.Length % 2 != 0)
            throw new ArgumentException("Route path must be an even number of bytes", nameof(routePath));

        int routeWords = routePath.Length / 2;
        bool padEmbed = (innerMr.Length % 2) != 0;
        int usLen = 2 + 2 + innerMr.Length + (padEmbed ? 1 : 0) + 2 + routePath.Length;
        var usData = new byte[usLen];
        int off = 0;
        usData[off++] = DefaultPriorityTick;
        usData[off++] = DefaultTimeoutTicks;
        BinaryPrimitives.WriteUInt16LittleEndian(usData.AsSpan(off, 2), (ushort)innerMr.Length); off += 2;
        innerMr.CopyTo(usData.AsSpan(off)); off += innerMr.Length;
        if (padEmbed) usData[off++] = 0;
        usData[off++] = (byte)routeWords;
        usData[off++] = 0; // reserved
        routePath.CopyTo(usData.AsSpan(off));

        var outerMr = new byte[2 + ConnectionManagerPath.Length + usData.Length];
        outerMr[0] = ServiceCode;
        outerMr[1] = (byte)(ConnectionManagerPath.Length / 2);
        ConnectionManagerPath.CopyTo(outerMr.AsSpan(2));
        usData.CopyTo(outerMr.AsSpan(2 + ConnectionManagerPath.Length));
        return outerMr;
    }

    /// <summary>
    /// Convenience: build an inner MR (service + path_size_words + path + service_data)
    /// suitable for feeding into <see cref="Wrap"/> or sending as bare MR.
    /// </summary>
    public static byte[] BuildInnerMr(byte serviceCode, byte[] pathBytes, ReadOnlySpan<byte> serviceData)
    {
        if (pathBytes.Length % 2 != 0)
            throw new ArgumentException("Path must be an even number of bytes", nameof(pathBytes));
        int pathWords = pathBytes.Length / 2;
        var buf = new byte[2 + pathBytes.Length + serviceData.Length];
        buf[0] = serviceCode;
        buf[1] = (byte)pathWords;
        pathBytes.CopyTo(buf.AsSpan(2));
        serviceData.CopyTo(buf.AsSpan(2 + pathBytes.Length));
        return buf;
    }
}
