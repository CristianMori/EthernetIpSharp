using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;

namespace EthernetIPSharp.Safety;

/// <summary>
/// CIP Safety Validator Object (Class 0x3A).
/// One instance per active safety connection. Manages CRC validation,
/// timestamp tracking, ping/time coordination, and fault detection.
/// </summary>
public sealed class SafetyValidatorObject
{
    public const uint ClassCode = 0x3A;

    private readonly CipClass _cipClass;
    private uint _nextInstanceId;

    public CipClass CipClass => _cipClass;

    public SafetyValidatorObject()
    {
        _cipClass = new CipClass(ClassCode, "Safety Validator", revision: 1);
        _cipClass.AddStandardInstanceServices();
    }

    /// <summary>
    /// Create a Safety Validator instance for a new safety connection.
    /// Sets up CRC seeds and initial state.
    /// </summary>
    public SafetyValidatorInstance CreateInstance(IoConnection connection)
    {
        _nextInstanceId++;
        var cipInstance = _cipClass.CreateInstance(_nextInstanceId);

        var validator = new SafetyValidatorInstance
        {
            InstanceId = _nextInstanceId,
            CipInstance = cipInstance,
            Connection = connection,
            State = SafetyValidatorState.Idle,
            PidSeedS1 = connection.SafetyPidSeedS1,
            PidSeedS3 = connection.SafetyPidSeedS3,
            PidSeedS5 = connection.SafetyPidSeedS5,
        };

        cipInstance.UserData = validator;

        // Add standard attributes
        cipInstance.AddAttribute(CipAttribute.Create(1, CipDataType.Usint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, (byte)validator.State));
        cipInstance.AddAttribute(CipAttribute.Create(2, CipDataType.Usint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, (byte)0)); // Type

        return validator;
    }

    /// <summary>Remove a validator instance when a safety connection closes.</summary>
    public void RemoveInstance(uint instanceId)
    {
        // CipClass doesn't have a RemoveInstance method, but for a simulator
        // we can leave the instance — it just won't be referenced.
    }
}

/// <summary>State of a Safety Validator instance.</summary>
public enum SafetyValidatorState : byte
{
    Idle = 0,
    Executing = 1,
    Faulted = 2,
}

/// <summary>Runtime state for a single safety connection's validator.</summary>
public sealed class SafetyValidatorInstance
{
    public uint InstanceId { get; init; }
    public CipInstance CipInstance { get; init; } = null!;
    public IoConnection Connection { get; init; } = null!;
    public SafetyValidatorState State { get; set; }

    // CRC seeds (precomputed from PID)
    public byte PidSeedS1 { get; init; }
    public ushort PidSeedS3 { get; init; }
    public uint PidSeedS5 { get; init; }

    // Runtime counters
    public ushort RolloverCount { get; set; }
    public ushort Timestamp { get; set; }
    public byte PingCount { get; set; }
    public uint PacketsProduced { get; set; }
    public uint PacketsConsumed { get; set; }
    public uint CrcErrors { get; set; }

    /// <summary>Advance the 128µs timestamp. Wraps at 0xFFFF and increments rollover.</summary>
    public void AdvanceTimestamp(ushort increment)
    {
        int next = Timestamp + increment;
        if (next > 0xFFFF)
        {
            RolloverCount++;
            Timestamp = (ushort)(next & 0xFFFF);
        }
        else
        {
            Timestamp = (ushort)next;
        }
    }
}
