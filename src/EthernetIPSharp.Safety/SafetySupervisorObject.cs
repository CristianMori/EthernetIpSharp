using System.Buffers.Binary;
using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Safety;

/// <summary>
/// CIP Safety Supervisor Object (Class 0x39).
/// One per device. Manages overall device safety state.
///
/// State machine: Idle → Self-Testing → Executing → Abort/Exception.
/// Must be present and configured before safety connections can be accepted.
/// </summary>
public sealed class SafetySupervisorObject
{
    public const uint ClassCode = 0x39;

    /// <summary>Service code for Propose_TUNID.</summary>
    public const byte ProposeTunidService = 0x56;

    /// <summary>Service code for Apply_TUNID.</summary>
    public const byte ApplyTunidService = 0x57;

    private readonly CipClass _cipClass;

    /// <summary>Pending proposed TUNID (set by Propose_TUNID, consumed by Apply_TUNID).</summary>
    private UniqueNetworkId? _proposedTunid;

    public CipClass CipClass => _cipClass;

    /// <summary>Current device safety state.</summary>
    public SafetySupervisorState State { get; set; } = SafetySupervisorState.Idle;

    /// <summary>Current device safety mode.</summary>
    public SafetySupervisorMode Mode { get; set; } = SafetySupervisorMode.Idle;

    /// <summary>Safety Network Number for this device.</summary>
    public SafetyNetworkNumber Snn { get; set; } = SafetyNetworkNumber.Zero;

    /// <summary>Safety Configuration Identifier.</summary>
    public SafetyConfigurationId Scid { get; set; }

    /// <summary>Target UNID for this device.</summary>
    public UniqueNetworkId Tunid { get; set; }

    /// <summary>Whether this device has had its TUNID assigned via Propose/Apply.</summary>
    public bool TunidAssigned { get; private set; }

    public SafetySupervisorObject(SafetyNetworkNumber snn, uint nodeAddress)
    {
        Snn = snn;
        Tunid = new UniqueNetworkId { Snn = snn, NodeAddress = nodeAddress };

        _cipClass = new CipClass(ClassCode, "Safety Supervisor", revision: 1);
        _cipClass.AddStandardInstanceServices();

        var inst = _cipClass.CreateInstance(1);

        // Attribute 1: State (USINT)
        inst.AddAttribute(CipAttribute.Create(1, CipDataType.Usint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, (byte)State));

        // Attribute 2: Mode (USINT)
        inst.AddAttribute(CipAttribute.Create(2, CipDataType.Usint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, (byte)Mode));

        // Attribute 3: Safety Network Number (6 bytes)
        var snnData = new byte[6];
        snn.CopyTo(snnData);
        inst.AddAttribute(new CipAttribute(3, CipDataType.Byte,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, snnData));

        // Attribute 4: Configuration Lock (USINT) — 0 = unlocked
        inst.AddAttribute(CipAttribute.Create(4, CipDataType.Usint,
            AttributeAccess.GetSingle | AttributeAccess.SetSingle | AttributeAccess.GetAll, (byte)0));

        // Service 0x54: Safety_Reset — resets ownership/configuration
        _cipClass.AddInstanceService(new CipServiceDefinition(0x54, "Safety_Reset", HandleSafetyReset));

        // Service 0x56: Propose_TUNID — PLC proposes a TUNID for this device
        _cipClass.AddInstanceService(new CipServiceDefinition(ProposeTunidService, "Propose_TUNID", HandleProposeTunid));

        // Service 0x57: Apply_TUNID — PLC confirms and applies the proposed TUNID
        _cipClass.AddInstanceService(new CipServiceDefinition(ApplyTunidService, "Apply_TUNID", HandleApplyTunid));

        // Attribute 6: Safety Configuration Identifier (SCID) — 10 bytes
        // SCCRC(4) + SCTS(6). Stored from Forward Open safety segment.
        var scidData = new byte[SafetyConfigurationId.Size]; // zeros = unconfigured
        inst.AddAttribute(new CipAttribute(6, CipDataType.Byte,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, scidData));

        // Attribute 25 (0x19): Configuration UNID (CFUNID) — 10 bytes
        // Who owns this device's configuration. 0 = unowned, accept any originator.
        var cfunid = new byte[UniqueNetworkId.Size]; // all zeros = unowned
        inst.AddAttribute(new CipAttribute(25, CipDataType.Byte,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, cfunid));

        // Attribute 27 (0x1B): Target UNID (TUNID) — 10 bytes
        // This device's own network identity: SNN(6) + NodeAddress(4)
        var tunidData = new byte[UniqueNetworkId.Size];
        Tunid.CopyTo(tunidData);
        inst.AddAttribute(new CipAttribute(27, CipDataType.Byte,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, tunidData));

        // Attribute 28 (0x1C): Output Connection Point Owners — struct
        // Number of entries (UINT) = 0 for now (no owned outputs)
        inst.AddAttribute(new CipAttribute(28, CipDataType.Uint,
            AttributeAccess.GetSingle | AttributeAccess.GetAll, new byte[] { 0x00, 0x00 }));
    }

    /// <summary>Transition to Executing state (ready for safety connections).</summary>
    public void Start()
    {
        State = SafetySupervisorState.Executing;
        Mode = SafetySupervisorMode.Run;
        UpdateStateAttribute();
    }

    /// <summary>Transition to Abort state (safety fault detected).</summary>
    public void Abort()
    {
        State = SafetySupervisorState.Abort;
        UpdateStateAttribute();
    }

    /// <summary>Reset from Abort back to Idle.</summary>
    public void Reset()
    {
        State = SafetySupervisorState.Idle;
        Mode = SafetySupervisorMode.Idle;
        UpdateStateAttribute();
    }

    /// <summary>
    /// Handle Safety_Reset service (0x54) on the Safety Supervisor.
    /// Reset types: 0=device reset, 1=return to factory defaults, 2=reset ownership.
    /// For type 2 (reset ownership): clears CFUNID, OCPUNID, and SCID.
    /// </summary>
    private CipServiceResponse HandleSafetyReset(CipInstance instance, CipServiceRequest request)
    {
        if (request.Data.Length < 1)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.NotEnoughData));

        byte resetType = request.Data.Span[0];

        switch (resetType)
        {
            case 0: // Device reset
            case 1: // Factory defaults
                Reset();
                return CipServiceResponse.Success(request.ServiceCode);

            case 2: // Reset ownership
                // Clear CFUNID (attr 25) to all zeros = unowned
                instance.GetAttribute(25)?.SetData(new byte[UniqueNetworkId.Size]);
                // Clear output connection point owners (attr 28)
                instance.GetAttribute(28)?.SetData([0x00, 0x00]);
                // Clear SCID and TUNID assignment
                Scid = default;
                TunidAssigned = false;
                _proposedTunid = null;
                return CipServiceResponse.Success(request.ServiceCode);

            default:
                return CipServiceResponse.Error(request.ServiceCode,
                    CipStatus.Error(CipStatus.InvalidParameter));
        }
    }

    /// <summary>
    /// Handle Propose_TUNID (0x56) — PLC proposes a TUNID for this device.
    /// Input: 10-byte UNID (SNN(6) + NodeAddress(4)).
    /// The NodeAddress must match our own node address.
    /// Stores the proposed TUNID for later Apply_TUNID.
    /// </summary>
    private CipServiceResponse HandleProposeTunid(CipInstance instance, CipServiceRequest request)
    {
        if (request.Data.Length < UniqueNetworkId.Size)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.NotEnoughData));

        var proposed = UniqueNetworkId.Parse(request.Data.Span);

        // All-0xFF means cancel pending proposal
        bool allFf = true;
        for (int i = 0; i < UniqueNetworkId.Size && allFf; i++)
            if (request.Data.Span[i] != 0xFF) allFf = false;

        if (allFf)
        {
            _proposedTunid = null;
            return CipServiceResponse.Success(request.ServiceCode);
        }

        // Store the proposal
        _proposedTunid = proposed;
        return CipServiceResponse.Success(request.ServiceCode);
    }

    /// <summary>
    /// Handle Apply_TUNID (0x57) — confirms and applies the previously proposed TUNID.
    /// Input: 10-byte UNID that must match the previously proposed TUNID.
    /// On success, updates the device TUNID (attr 27) and SNN (attr 3).
    /// </summary>
    private CipServiceResponse HandleApplyTunid(CipInstance instance, CipServiceRequest request)
    {
        if (request.Data.Length < UniqueNetworkId.Size)
            return CipServiceResponse.Error(request.ServiceCode, CipStatus.Error(CipStatus.NotEnoughData));

        if (_proposedTunid == null)
            return CipServiceResponse.Error(request.ServiceCode,
                CipStatus.Error(0x0C)); // Object state conflict — no pending proposal

        var applied = UniqueNetworkId.Parse(request.Data.Span);

        // Must match the previously proposed TUNID
        var propData = new byte[UniqueNetworkId.Size];
        _proposedTunid.Value.CopyTo(propData);
        var applyData = new byte[UniqueNetworkId.Size];
        applied.CopyTo(applyData);
        if (!propData.AsSpan().SequenceEqual(applyData))
            return CipServiceResponse.Error(request.ServiceCode,
                CipStatus.Error(CipStatus.InvalidParameter));

        // Apply the TUNID
        Tunid = applied;
        Snn = applied.Snn;
        TunidAssigned = true;
        _proposedTunid = null;

        // Update attr 27 (TUNID) and attr 3 (SNN)
        var tunidBytes = new byte[UniqueNetworkId.Size];
        Tunid.CopyTo(tunidBytes);
        instance.GetAttribute(27)?.SetData(tunidBytes);

        var snnBytes = new byte[6];
        Snn.CopyTo(snnBytes);
        instance.GetAttribute(3)?.SetData(snnBytes);

        return CipServiceResponse.Success(request.ServiceCode);
    }

    private void UpdateStateAttribute()
    {
        var inst = _cipClass.GetInstance(1);
        if (inst != null)
        {
            inst.GetAttribute(1)?.SetData([(byte)State]);
            inst.GetAttribute(2)?.SetData([(byte)Mode]);
        }
    }
}

/// <summary>Safety Supervisor device states.</summary>
public enum SafetySupervisorState : byte
{
    Idle = 0,
    SelfTesting = 1,
    Executing = 2,
    Abort = 3,
    Exception = 4,
    WaitForLock = 5,
}

/// <summary>Safety Supervisor device modes.</summary>
public enum SafetySupervisorMode : byte
{
    Idle = 0,
    Configuration = 1,
    Run = 2,
}
