using System.Net.Sockets;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// Bounds a TCP connect attempt. Internal; see the public ConnectTimeout
/// property on the client types.
/// </summary>
internal static class TcpConnectHelper
{
    /// <summary>Default value of the public ConnectTimeout properties.</summary>
    internal static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(5);

    internal static TimeSpan? Normalize(TimeSpan? value)
    {
        if (value is { } v && v != Timeout.InfiniteTimeSpan && v <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(value), "Timeout must be positive or infinite.");
        return value is { } t && t == Timeout.InfiniteTimeSpan ? null : value;
    }

    /// <summary>
    /// Run <paramref name="connect"/> under <paramref name="timeout"/>. On expiry the
    /// attempt is cancelled, <paramref name="client"/> is disposed and a
    /// <see cref="TimeoutException"/> is thrown. A cancelled <paramref name="ct"/>
    /// surfaces as <see cref="OperationCanceledException"/> (client also disposed);
    /// socket errors propagate unchanged.
    /// </summary>
    internal static async Task ConnectAsync(
        TcpClient client, Func<CancellationToken, ValueTask> connect,
        string host, int port, TimeSpan? timeout, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeout is { } t) linked.CancelAfter(t);
        try
        {
            await connect(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && timeout is { } expired)
        {
            client.Dispose();
            throw new TimeoutException(
                $"TCP connect to {host}:{port} timed out after {expired.TotalMilliseconds:0} ms (ConnectTimeout).");
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }
}
