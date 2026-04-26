namespace EipSim.Protocol;

/// <summary>
/// Configuration for establishing an I/O connection via Forward Open.
/// </summary>
public sealed class ForwardOpenConfig
{
    /// <summary>Assembly instance the scanner sends O→T data to (consumed by target).</summary>
    public uint ConsumedAssembly { get; init; }

    /// <summary>Assembly instance the target sends T→O data from (produced by target).</summary>
    public uint ProducedAssembly { get; init; }

    /// <summary>Configuration assembly instance.</summary>
    public uint ConfigAssembly { get; init; }

    /// <summary>O→T data size in bytes (application data, excluding headers).</summary>
    public ushort ConsumedSize { get; init; }

    /// <summary>T→O data size in bytes (application data, excluding headers).</summary>
    public ushort ProducedSize { get; init; }

    /// <summary>Requested Packet Interval in microseconds.</summary>
    public uint Rpi { get; init; } = 10_000; // 10ms default

    /// <summary>Transport class: 0 = Class 0, 1 = Class 1.</summary>
    public byte TransportClass { get; init; } = 1; // Class 1 default

    /// <summary>Connection timeout multiplier (0=x4, 1=x8, 2=x16, ...).</summary>
    public byte TimeoutMultiplier { get; init; } = 2; // x16

    public bool IsClass1 => TransportClass == 1;
}
