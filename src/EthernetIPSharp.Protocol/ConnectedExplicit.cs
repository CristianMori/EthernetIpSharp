using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Protocol;

/// <summary>
/// Class 3 connected-explicit messaging from the scanner side. Backed by a
/// Class 3 Forward Open to the target's Message Router; subsequent
/// SendAsync / SendRawAsync calls travel over TCP via SendUnitData
/// (encap 0x70) instead of SendRRData.
/// </summary>
public sealed class ConnectedExplicit : IAsyncDisposable
{
    private readonly EipScanner _scanner;
    private readonly uint _otoTConnectionId;
    private readonly uint _ttoOConnectionId;
    private readonly ushort _connectionSerial;
    private readonly ushort _originatorVendor;
    private readonly uint _originatorSerial;
    private int _seqCount;
    private bool _open = true;
    private readonly SemaphoreSlim _lock = new(1, 1);

    /// <summary>True until <see cref="CloseAsync"/> is called.</summary>
    public bool IsOpen => _open;

    internal ConnectedExplicit(EipScanner scanner,
                                 uint otoTConnectionId, uint ttoOConnectionId,
                                 ushort connectionSerial,
                                 ushort originatorVendor, uint originatorSerial)
    {
        _scanner = scanner;
        _otoTConnectionId = otoTConnectionId;
        _ttoOConnectionId = ttoOConnectionId;
        _connectionSerial = connectionSerial;
        _originatorVendor = originatorVendor;
        _originatorSerial = originatorSerial;
    }

    /// <summary>Send a request addressed by class + instance (+ optional attribute).
    /// Builds the EPATH via <see cref="PathBuilder.BuildPath"/>.</summary>
    public Task<CipServiceResponse> SendAsync(byte serviceCode,
                                                 uint classId, uint instanceId,
                                                 ushort? attributeId = null,
                                                 ReadOnlyMemory<byte> data = default,
                                                 CancellationToken ct = default)
    {
        var path = PathBuilder.BuildPath(classId, instanceId, attributeId);
        return SendRawAsync(serviceCode, path, data, ct);
    }

    /// <summary>Send a request with an already-encoded EPATH (e.g. symbolic /
    /// multi-element path).</summary>
    public async Task<CipServiceResponse> SendRawAsync(byte serviceCode,
                                                         ReadOnlyMemory<byte> pathBytes,
                                                         ReadOnlyMemory<byte> data = default,
                                                         CancellationToken ct = default)
    {
        if (!_open) throw new InvalidOperationException("ConnectedExplicit: closed");

        await _lock.WaitAsync(ct);
        ushort seq;
        try
        {
            _seqCount = (_seqCount + 1) & 0xFFFF;
            seq = (ushort)_seqCount;
        }
        finally
        {
            _lock.Release();
        }
        return await _scanner.SendConnectedMrAsync(_otoTConnectionId, seq,
                                                      serviceCode, pathBytes, data, ct);
    }

    /// <summary>Close the underlying Class 3 connection (sends Forward Close).</summary>
    public async Task CloseAsync(CancellationToken ct = default)
    {
        if (!_open) return;
        _open = false;
        try
        {
            await _scanner.ForwardCloseAsync(_connectionSerial, _originatorVendor,
                                                _originatorSerial, ct);
        }
        catch { /* best-effort */ }
    }

    public async ValueTask DisposeAsync()
    {
        await CloseAsync();
        _lock.Dispose();
    }
}
