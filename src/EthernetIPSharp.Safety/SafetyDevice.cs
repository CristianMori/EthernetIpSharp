using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Connections;
using EthernetIPSharp.Device;
using EthernetIPSharp.Protocol;

namespace EthernetIPSharp.Safety;

/// <summary>
/// CIP Safety EtherNet/IP device.
/// Handles safety frame encoding/decoding, time coordination (TCOO),
/// CRC seed computation, and safety connection lifecycle.
/// </summary>
public sealed class SafetyDevice : VirtualDevice, ISafetyConnectionHandler
{
    private readonly SafetySupervisorObject _supervisor;
    private readonly SafetyValidatorObject _validator;

    // When we are the data consumer (server-direction safety connection),
    // the SafetyOpen response carries Initial_TS / Initial_Rollover_Value
    // generated from our local clock. The rollover value uses an offset that
    // increments each time we accept such a connection, ensuring distinct seeds.
    private static int _initialRcOffset;

    /// <summary>
    /// Enable per-frame and per-TCOO diagnostic logging to the console. Default
    /// false — Console.WriteLine on the hot path holds a global lock and can
    /// stall the production thread when the console is busy. Set to true only
    /// when actively debugging a connection issue.
    /// </summary>
    public static bool EnableTrace { get; set; }

    /// <summary>Number of seconds at the start of each safety connection during
    /// which per-frame trace lines are emitted unconditionally (mode, ts, CTCV,
    /// CRC validity). Set to 0 to disable. Useful for diagnosing the short
    /// 0.1–1s connection failures that happen at adapter restart.</summary>
    public static int StartupTraceSeconds { get; set; }

    // ISafetyConnectionHandler
    public ushort VendorId => Identity.VendorId;
    public uint SerialNumber => Identity.SerialNumber;

    public SafetyDevice(IdentityInfo identity, IPAddress bindAddress,
        SafetyNetworkNumber snn, uint nodeAddress, string? name = null)
        : base(identity, bindAddress, name)
    {
        _supervisor = new SafetySupervisorObject(snn, nodeAddress);
        _validator = new SafetyValidatorObject();

        Dispatcher.RegisterClass(_supervisor.CipClass);
        Dispatcher.RegisterClass(_validator.CipClass);

        ConnectionManager.SafetyHandler = this;
        ConnectionManager.ConnectionRemoved += OnConnectionRemoved;

        _supervisor.Start();
    }

    // ==================== ISafetyConnectionHandler ====================

    public ushort? ValidateSafetyOpen(ReadOnlyMemory<byte> safetySegment, ForwardOpenRequest fwdOpen)
    {
        if (safetySegment.Length < 3 || safetySegment.Span[0] != 0x50)
            return 0x080E;

        var (seg, _) = SafetyNetworkSegment.Parse(safetySegment.Span);

        // 1. Verify TUNID
        var ourTunid = new byte[UniqueNetworkId.Size];
        _supervisor.Tunid.CopyTo(ourTunid);
        var segTunid = new byte[UniqueNetworkId.Size];
        seg.Tunid.CopyTo(segTunid);
        if (!ourTunid.AsSpan().SequenceEqual(segTunid))
            return 0x080E;

        // 2. Validate CPCRC
        {
            var sd = fwdOpen.RawServiceData.Span;
            var connPath = fwdOpen.ConnectionPath;

            int safetyOff = 0;
            for (int i = 0; i < connPath.Length - 1; i++)
                if (connPath.Span[i] == 0x50) { safetyOff = i; break; }

            var eKeyAppPath = connPath.Slice(0, safetyOff);
            int nsdSize = seg.Format == 0x02 ? 50 : 48;
            var nsdBytes = connPath.Slice(safetyOff, nsdSize);

            var crcBuf = new byte[4 + 18 + eKeyAppPath.Length + nsdSize];
            int off = 0;
            sd.Slice(10, 4).CopyTo(crcBuf.AsSpan(off)); off += 4;
            sd.Slice(18, 18).CopyTo(crcBuf.AsSpan(off)); off += 18;
            eKeyAppPath.Span.CopyTo(crcBuf.AsSpan(off)); off += eKeyAppPath.Length;
            nsdBytes.Span.CopyTo(crcBuf.AsSpan(off)); off += nsdSize;

            uint computedCpcrc = SafetyCrc.ComputeS4(crcBuf.AsSpan(0, off));
            if (computedCpcrc != seg.Cpcrc)
            {
                Console.WriteLine($"[SAFETY] CPCRC mismatch: computed=0x{computedCpcrc:X8} received=0x{seg.Cpcrc:X8}");
                return 0x080D;
            }
        }

        // 3. Check SCID
        bool hasScid = _supervisor.Scid.Sccrc != 0;
        if (!hasScid) return null;

        // 4. Type 2a: non-zero SCID must match
        if (seg.Sccrc != 0 && seg.Sccrc != _supervisor.Scid.Sccrc)
            return 0x0111;

        return null;
    }

    public void ConfigureSafetyConnection(IoConnection conn, ForwardOpenRequest fwdOpen)
    {
        bool isServer = (fwdOpen.TransportClassTrigger & 0x80) != 0;

        if (conn.SafetySegmentData.Length >= 3 && conn.SafetySegmentData.Span[0] == 0x50)
        {
            var (safetySeg, _) = SafetyNetworkSegment.Parse(conn.SafetySegmentData.Span);
            var svInst = _supervisor.CipClass.GetInstance(1);

            var cfunidData = new byte[UniqueNetworkId.Size];
            safetySeg.Ounid.CopyTo(cfunidData);
            svInst?.GetAttribute(25)?.SetData(cfunidData);

            var scidData = new byte[SafetyConfigurationId.Size];
            BinaryPrimitives.WriteUInt32LittleEndian(scidData, safetySeg.Sccrc);
            if (safetySeg.Scts != null)
                safetySeg.Scts.CopyTo(scidData.AsSpan(4));
            svInst?.GetAttribute(6)?.SetData(scidData);
            _supervisor.Scid = new SafetyConfigurationId
            {
                Sccrc = safetySeg.Sccrc,
                Scts = safetySeg.Scts != null ? new SafetyNetworkNumber(safetySeg.Scts) : SafetyNetworkNumber.Zero,
            };

            // Initial_TS / Initial_Rollover_Value handling for single-cast safety:
            //   - TARGET PRODUCER (client direction, we produce): echo the
            //     originator's values; both sides start from them.
            //   - TARGET CONSUMER (server direction, we consume): we generate fresh
            //     values from our local clock; the originator (producer) will start
            //     from the values we send in the response.
            if (isServer)
            {
                // PLC caches our InitialRolloverValue per device identity — if
                // we send a different value on reconnect, PLC keeps using the
                // previously cached one and CRC validation diverges. Use a
                // deterministic value (0) so PLC's cache is always consistent
                // with what we use to decode incoming frames.
                conn.SafetyInitialTimestamp = 0;
                conn.SafetyInitialRolloverValue = 0;
            }
            else
            {
                conn.SafetyInitialTimestamp = safetySeg.InitialTimeStamp;
                conn.SafetyInitialRolloverValue = safetySeg.InitialRolloverValue;
            }

            if (StartupTraceSeconds > 0)
                Console.WriteLine($"[CONFIG] conn={conn.ConnectionSerialNumber:X4} isServer={isServer} InitialTS=0x{conn.SafetyInitialTimestamp:X4} InitialRV=0x{conn.SafetyInitialRolloverValue:X4}");
            conn.SafetyPingIntervalUs = (long)safetySeg.PingIntervalMultiplier * conn.TtoORpi;

            // Connection_Correction_Constant = Time_Drift_Constant + 1 - Time_Coord_Msg_Min_Multiplier
            // Time_Drift_Constant = Roundup((Timeout_Mult+1) * EPI * PingIntMult / 320000)
            long epiUs = conn.TtoORpi;
            long timeDriftConst = ((safetySeg.TimeoutMultiplier + 1L)
                * epiUs * safetySeg.PingIntervalMultiplier + 319999) / 320000;
            if (timeDriftConst < 1) timeDriftConst = 1;
            conn.SafetyConnectionCorrectionConstant = (ushort)(timeDriftConst + 1
                - safetySeg.TimeCoordMsgMinMultiplier);
        }

        // Enable per-frame trace logs for the first StartupTraceSeconds of the
        // connection — diagnoses the short 0.1–1s failures at restart.
        if (StartupTraceSeconds > 0)
            conn.SafetyStartupTraceUntilTicks = Stopwatch.GetTimestamp()
                + (long)StartupTraceSeconds * Stopwatch.Frequency;

        var vi = _validator.CreateInstance(conn);
        vi.State = SafetyValidatorState.Executing;
        ushort svInstId = (ushort)vi.InstanceId;

        // Target PID — for data WE produce on T→O
        conn.SafetyPidSeedS1 = SafetyCrc.PidCidSeedS1(Identity.VendorId, Identity.SerialNumber, svInstId);
        conn.SafetyPidSeedS3 = SafetyCrc.PidCidSeedS3(Identity.VendorId, Identity.SerialNumber, svInstId);
        conn.SafetyPidSeedS5 = SafetyCrc.PidCidSeedS5(Identity.VendorId, Identity.SerialNumber, svInstId);

        // Originator PID — for verifying data ORIGINATOR produces on O→T
        conn.SafetyOriginatorPidSeedS1 = SafetyCrc.PidCidSeedS1(
            fwdOpen.OriginatorVendorId, fwdOpen.OriginatorSerialNumber, fwdOpen.ConnectionSerialNumber);
        conn.SafetyOriginatorPidSeedS3 = SafetyCrc.PidCidSeedS3(
            fwdOpen.OriginatorVendorId, fwdOpen.OriginatorSerialNumber, fwdOpen.ConnectionSerialNumber);
        conn.SafetyOriginatorPidSeedS5 = SafetyCrc.PidCidSeedS5(
            fwdOpen.OriginatorVendorId, fwdOpen.OriginatorSerialNumber, fwdOpen.ConnectionSerialNumber);

        // CID = CONSUMER's identity + CONSUMER's connection serial
        if (isServer)
        {
            conn.SafetyCidSeedS3 = SafetyCrc.PidCidSeedS3(Identity.VendorId, Identity.SerialNumber, svInstId);
            conn.SafetyCidSeedS5 = SafetyCrc.PidCidSeedS5(Identity.VendorId, Identity.SerialNumber, svInstId);
        }
        else
        {
            conn.SafetyCidSeedS3 = SafetyCrc.PidCidSeedS3(
                fwdOpen.OriginatorVendorId, fwdOpen.OriginatorSerialNumber, fwdOpen.ConnectionSerialNumber);
            conn.SafetyCidSeedS5 = SafetyCrc.PidCidSeedS5(
                fwdOpen.OriginatorVendorId, fwdOpen.OriginatorSerialNumber, fwdOpen.ConnectionSerialNumber);
        }

        conn.SafetyValidatorInstanceId = svInstId;
        conn.SafetyLastPingCount = 0xFF;
    }

    // ==================== Virtual Overrides ====================

    protected override void OnConnectionReady(IoConnection conn)
    {
        // Start producing immediately on FwdOpen. Until the first TCOO arrives,
        // ProduceIoData sends IDLE frames (runIdle=false, timestamp=0) — that
        // keeps the safety connection alive within the originator's timeout.
        // At higher RPIs (e.g. 20ms) PLC may not send its first TCOO for several
        // seconds, which exceeds the 200ms safety timeout if we wait silent.
        base.OnConnectionReady(conn);
    }

    protected override void ProduceIoData(IoConnection conn)
    {
        if (!conn.IsSafety) { base.ProduceIoData(conn); return; }
        if (conn.State != ConnectionState.Established) return;

        var assembly = Assemblies.GetAssembly(conn.ProducedAssemblyInstance);
        if (assembly == null) return;

        // TCOO-only direction
        if (conn.TtoOSize == 6 && assembly.DataSize == 0)
            return;

        int baseDataSize = SafetyFrameCodec.WireSize(assembly.DataSize, SafetyFormat.Base);
        int extDataSize = SafetyFrameCodec.WireSize(assembly.DataSize, SafetyFormat.Extended);
        if (conn.TtoOSize != baseDataSize && conn.TtoOSize != extDataSize)
            return;

        var format = conn.SafetyFormat == 0x02 ? SafetyFormat.Extended : SafetyFormat.Base;
        bool consumerActive = conn.SafetyConsumerActive;
        bool runIdle = consumerActive;

        ushort timestamp;
        if (consumerActive)
        {
            // Compute raw producer timestamp from wall clock. Also remember
            // this moment as the last-frame-sent time, so the TCOO handler
            // can reject TCOOs that arrive an anomalously long time after
            // our most recent send (those carry a CTV biased by the delay,
            // which causes proposed_CTCV to jump even when the PLC clock
            // hasn't actually drifted).
            long nowTicks = Stopwatch.GetTimestamp();
            conn.SafetyLastFrameSentTicks = nowTicks;
            long elapsedUs = (nowTicks - conn.SafetyProductionStartTicks)
                * 1_000_000 / Stopwatch.Frequency;
            long rawTicks = conn.SafetyInitialTimestamp + elapsedUs / 128;
            ushort rawTimestamp = (ushort)(rawTicks & 0xFFFF);
            conn.SafetyLastProducedTimestamp = rawTimestamp;

            // Slew the applied CTCV toward the goal set by the most recent TCOO.
            // Step size = max(1, remaining/8) per frame so big jumps settle in
            // about 8 frames (still gentle) while small drifts move at 1/frame.
            ushort goal = conn.SafetyConsumerTimeCorrectionGoal;
            ushort applied = conn.SafetyConsumerTimeCorrectionValue;
            if (applied != goal)
            {
                short slewDelta = (short)(goal - applied);
                if (slewDelta > 0)
                {
                    int step = Math.Max(1, slewDelta / 8);
                    if (step > slewDelta) step = slewDelta;
                    conn.SafetyConsumerTimeCorrectionValue = (ushort)(applied + step);
                }
                else
                {
                    // Goal moved backward (shouldn't happen because TCOO handler
                    // refuses negative-delta updates, but be defensive).
                    conn.SafetyConsumerTimeCorrectionValue = goal;
                }
            }

            // Apply Consumer_Time_Correction_Value
            long correctedTicks = rawTicks + conn.SafetyConsumerTimeCorrectionValue;
            long prevSentTicks = conn.SafetyLastSentTicks;

            // Forward-only guard using full 64-bit tick comparison (no modular ambiguity).
            // If the corrected ticks would go backward vs. the last sent, force one tick
            // forward instead — protects against CTCV jumps that would cause regressions.
            long deltaTicks = correctedTicks - prevSentTicks;
            if (prevSentTicks != 0 && deltaTicks < 0)
            {
                if (EnableTrace)
                    Console.WriteLine($"[GUARD] conn={conn.ConnectionSerialNumber:X4} rawTicks={rawTicks} correctedTicks={correctedTicks} prevSentTicks={prevSentTicks} deltaTicks={deltaTicks} CTCV={conn.SafetyConsumerTimeCorrectionValue} -> force prevSent+1");
                correctedTicks = prevSentTicks + 1;
            }

            ushort candidateTs = (ushort)(correctedTicks & 0xFFFF);
            timestamp = candidateTs;
            conn.SafetyTimestamp = timestamp;
            conn.SafetyLastSentTicks = correctedTicks;
            conn.SafetyRolloverCount = (ushort)(conn.SafetyInitialRolloverValue + (correctedTicks >> 16));

            // Periodic frame snapshot (every 1000th frame ≈ every 3s at 5ms RPI)
            if (EnableTrace && (conn.EncapsulationSequenceNumber % 1000) == 0)
                Console.WriteLine($"[FRAME] conn={conn.ConnectionSerialNumber:X4} seq={conn.EncapsulationSequenceNumber} raw={rawTimestamp} sent={timestamp} CTCV={conn.SafetyConsumerTimeCorrectionValue}");

            // Startup phase: log every outgoing data frame so we can see what's
            // on the wire during the failed 0.1–1s startup windows.
            if (conn.SafetyStartupTraceUntilTicks > 0
                && Stopwatch.GetTimestamp() < conn.SafetyStartupTraceUntilTicks)
            {
                Console.WriteLine($"[SU-SEND] conn={conn.ConnectionSerialNumber:X4} seq={conn.EncapsulationSequenceNumber} raw={rawTimestamp} CTCV={conn.SafetyConsumerTimeCorrectionValue} wire_ts={timestamp}");
            }
        }
        else
        {
            timestamp = 0;
        }

        if (consumerActive)
        {
            // Ping increment — BEFORE creating mode byte
            long now = Stopwatch.GetTimestamp();
            if (conn.SafetyLastPingChangeTicks == 0)
                conn.SafetyLastPingChangeTicks = now;
            long pingElapsedUs = (now - conn.SafetyLastPingChangeTicks) * 1_000_000 / Stopwatch.Frequency;
            if (conn.SafetyPingIntervalUs > 0 && pingElapsedUs >= conn.SafetyPingIntervalUs)
            {
                conn.SafetyLastPingChangeTicks = now;
                conn.SafetyPingCount = (byte)((conn.SafetyPingCount + 1) & 0x03);
            }
        }

        var mode = ModeByte.Create(runIdle: runIdle, pingCount: conn.SafetyPingCount);

        // Hot path — no per-frame heap allocations. The assembly data is small
        // (typically 1–8 bytes) so stackalloc is safe and avoids gen0 churn.
        Span<byte> asmData = stackalloc byte[assembly.DataSize];
        assembly.CopyDataTo(asmData);

        var safetyBuf = ArrayPool<byte>.Shared.Rent(assembly.DataSize * 2 + 16);
        try
        {
            int safetyLen = SafetyFrameCodec.Encode(safetyBuf, asmData, format, mode, timestamp,
                conn.SafetyPidSeedS1, conn.SafetyPidSeedS3, conn.SafetyPidSeedS5,
                conn.SafetyRolloverCount);

            if (safetyLen > 0)
                SendUdpIoData(conn, safetyBuf.AsSpan(0, safetyLen));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(safetyBuf);
        }
    }

    protected override void HandleReceivedIoData(IoConnection conn, ReadOnlyMemory<byte> data)
    {
        if (!conn.IsSafety) { base.HandleReceivedIoData(conn, data); return; }

        int wireSize = data.Length;

        // TCOO received from PLC consumer
        if (wireSize == 6 || wireSize == 5)
        {
            if (!conn.SafetyConsumerActive)
            {
                conn.SafetyConsumerActive = true;
                conn.SafetyTimestamp = conn.SafetyInitialTimestamp;
                conn.SafetyRolloverCount = conn.SafetyInitialRolloverValue;
                conn.SafetyProductionStartTicks = Stopwatch.GetTimestamp();
            }

            // Extract Consumer_Time_Value and compute time correction
            if (data.Length >= 3)
            {
                ushort consumerTimeValue = BinaryPrimitives.ReadUInt16LittleEndian(data.Span.Slice(1));

                if (conn.SafetyStartupTraceUntilTicks > 0
                    && Stopwatch.GetTimestamp() < conn.SafetyStartupTraceUntilTicks)
                {
                    long sendGapUs = conn.SafetyLastFrameSentTicks != 0
                        ? (Stopwatch.GetTimestamp() - conn.SafetyLastFrameSentTicks)
                            * 1_000_000 / Stopwatch.Frequency
                        : -1;
                    Console.WriteLine($"[SU-RECV-TCOO] conn={conn.ConnectionSerialNumber:X4} ctv={consumerTimeValue} ack=0x{data.Span[0]:X2} lastRaw={conn.SafetyLastProducedTimestamp} CTCV={conn.SafetyConsumerTimeCorrectionValue} sendGap={sendGapUs}us");
                }

                // Outlier check: proposed_CTCV is biased by the time elapsed
                // between our last sent frame and TCOO arrival (because
                // SafetyLastProducedTimestamp is from that older frame). In
                // steady state TCOOs arrive 0.3–0.5ms after our send. When
                // the PLC's task is briefly stalled, the TCOO arrives 3–8ms
                // late, and the resulting proposed_CTCV jump (20–60 ticks)
                // gets applied and triggers a FwdClose. Reject TCOOs whose
                // send-to-arrival gap exceeds 2ms (≈ 16 ticks).
                if (conn.SafetyLastFrameSentTicks != 0)
                {
                    long sendToTcooUs = (Stopwatch.GetTimestamp()
                        - conn.SafetyLastFrameSentTicks)
                        * 1_000_000 / Stopwatch.Frequency;
                    const long lateThresholdUs = 2_000; // 2ms
                    if (sendToTcooUs > lateThresholdUs)
                    {
                        if (EnableTrace)
                            Console.WriteLine($"[TCOO-LATE] conn={conn.ConnectionSerialNumber:X4} ctv={consumerTimeValue} sendToTcoo={sendToTcooUs}us (>{lateThresholdUs}us) — skipping CTCV update");
                        return;
                    }
                }

                // Worst_Case_CTCV = Consumer_Time_Value - Producer_Rcved_Time_Value - Connection_Correction_Constant
                ushort worstCaseCTCV = (ushort)(consumerTimeValue
                    - conn.SafetyLastProducedTimestamp
                    - conn.SafetyConnectionCorrectionConstant);

                ushort oldCTCV = conn.SafetyConsumerTimeCorrectionValue;
                short deltaCTCV = (short)(worstCaseCTCV - oldCTCV);

                if (!conn.SafetyTimeCorrectionInitialized)
                {
                    // First TCOO: no valid LastProducedTimestamp yet, skip correction
                    conn.SafetyTimeCorrectionInitialized = true;
                    if (EnableTrace)
                        Console.WriteLine($"[CTCV-INIT] conn={conn.ConnectionSerialNumber:X4} ctv={consumerTimeValue} lastRaw={conn.SafetyLastProducedTimestamp} CCC={conn.SafetyConnectionCorrectionConstant} would_be_CTCV={worstCaseCTCV} (SKIPPED first TCOO)");
                }
                else
                {
                    // Subsequent TCOOs — adaptive correction:
                    //   - Negative delta: skip entirely (CTCV never moves backward).
                    //   - Small positive delta (<= one RPI of ticks): apply instantly.
                    //     PLC's per-frame validation tolerates this; gradual slew
                    //     would actually keep producing "wrong" timestamps for
                    //     several frames while it converges.
                    //   - Large positive delta: set goal only and let ProduceIoData
                    //     slew toward it (1/8 + min 1 per frame) so a single huge
                    //     hiccup can't cause a one-shot timestamp jump.
                    int instantApplyThreshold = (int)(conn.TtoORpi / 128);
                    if (instantApplyThreshold < 1) instantApplyThreshold = 1;

                    ushort newApplied = oldCTCV;
                    ushort newGoal = conn.SafetyConsumerTimeCorrectionGoal;
                    string note;
                    if (deltaCTCV <= 0)
                    {
                        note = "skipped (delta <= 0)";
                    }
                    else if (oldCTCV == 0)
                    {
                        // First real CTCV computation (initial value never applied
                        // before). Apply instantly — otherwise the slow slew leaves
                        // our timestamps drifting for ~30 frames, which appears to
                        // correlate with PLC closing the connection at the first
                        // ping wrap.
                        newApplied = worstCaseCTCV;
                        newGoal = worstCaseCTCV;
                        note = $"applied instantly (first real CTCV, delta={deltaCTCV})";
                    }
                    else if (deltaCTCV <= instantApplyThreshold)
                    {
                        newApplied = worstCaseCTCV;
                        newGoal = worstCaseCTCV;
                        note = $"applied instantly (delta={deltaCTCV} <= {instantApplyThreshold})";
                    }
                    else
                    {
                        // Big jump — set goal only, slew in ProduceIoData.
                        if ((short)(worstCaseCTCV - newGoal) > 0)
                            newGoal = worstCaseCTCV;
                        note = $"slewing (delta={deltaCTCV} > {instantApplyThreshold}, goal={newGoal})";
                    }
                    conn.SafetyConsumerTimeCorrectionValue = newApplied;
                    conn.SafetyConsumerTimeCorrectionGoal = newGoal;
                    if (EnableTrace)
                        Console.WriteLine($"[CTCV] conn={conn.ConnectionSerialNumber:X4} ctv={consumerTimeValue} lastRaw={conn.SafetyLastProducedTimestamp} CCC={conn.SafetyConnectionCorrectionConstant} oldCTCV={oldCTCV} proposed={worstCaseCTCV} -> {note} appliedCTCV={newApplied}");
                }
            }

            return;
        }

        // Decode safety data
        var format = conn.SafetyFormat == 0x02 ? SafetyFormat.Extended : SafetyFormat.Base;
        int dataLen = EstimateDataLength(wireSize);
        if (dataLen <= 0) return;

        // Track ORIGINATOR's rollover count separately from our producer's.
        // Extended-Format CRC includes rolloverCount in the seed, so the
        // value we use for decoding must match what PLC used to encode.
        // Both ends start at SafetyInitialRolloverValue (per spec: target
        // consumer generates these, originator uses them) and increment when
        // the wire timestamp wraps 0xFFFF→0x0000.
        ushort incomingTs = SafetyFrameCodec.ExtractTimestamp(data.Span, dataLen, format);
        if (!conn.SafetyOriginatorRolloverInitialized)
        {
            conn.SafetyOriginatorRolloverCount = conn.SafetyInitialRolloverValue;
            conn.SafetyOriginatorLastTs = incomingTs;
            conn.SafetyOriginatorRolloverInitialized = true;
        }
        else
        {
            // Wrap = current ts is much less than previous (delta > half-range
            // backwards). Producers always increase ts monotonically, so a
            // big backward jump means wraparound.
            int delta = incomingTs - conn.SafetyOriginatorLastTs;
            if (delta < -0x4000)
                conn.SafetyOriginatorRolloverCount = (ushort)(conn.SafetyOriginatorRolloverCount + 1);
            conn.SafetyOriginatorLastTs = incomingTs;
        }

        var result = SafetyFrameCodec.Decode(data.Span, dataLen, format,
            conn.SafetyOriginatorPidSeedS1, conn.SafetyOriginatorPidSeedS3, conn.SafetyOriginatorPidSeedS5,
            conn.SafetyOriginatorRolloverCount);

        // IDLE frames may precede PLC's processing of our SafetyOpen response —
        // PLC encodes them with rolloverCount=0 (its default) instead of our
        // SafetyInitialRolloverValue. Retry with 0 if first attempt failed and
        // the frame is in idle mode (run bit = 0).
        if (!result.CrcValid && dataLen < data.Length && (data.Span[dataLen] & 0x80) == 0
            && conn.SafetyOriginatorRolloverCount != 0)
        {
            result = SafetyFrameCodec.Decode(data.Span, dataLen, format,
                conn.SafetyOriginatorPidSeedS1, conn.SafetyOriginatorPidSeedS3, conn.SafetyOriginatorPidSeedS5,
                0);
        }

        // Only write to the assembly if the CRC is valid. Protocol responses
        // (TCOO, ping tracking) still proceed since the mode byte is at a fixed
        // offset and the PLC needs them to keep the connection alive.
        if (result.CrcValid)
            Assemblies.GetAssembly(conn.ConsumedAssemblyInstance)?.SetData(result.ActualData);

        // Extract mode byte
        byte modeByte = dataLen < data.Length ? data.Span[dataLen] : (byte)0;
        byte currentPing = (byte)(modeByte & 0x03);
        bool plcRunning = (modeByte & 0x80) != 0;

        if (conn.SafetyStartupTraceUntilTicks > 0
            && Stopwatch.GetTimestamp() < conn.SafetyStartupTraceUntilTicks)
        {
            Console.WriteLine($"[SU-RECV-DATA] conn={conn.ConnectionSerialNumber:X4} mode=0x{modeByte:X2} ts={result.Timestamp} wireTs={incomingTs} crc={(result.CrcValid ? "OK" : "BAD")} rc=0x{conn.SafetyOriginatorRolloverCount:X4} ping={currentPing}");
        }

        // Detect ping change → send TCOO
        if (currentPing != conn.SafetyLastPingCount)
        {
            conn.SafetyLastPingCount = currentPing;
            SendTimeCoordination(conn);
        }

        // On the false→true transition of PLC run state, send cold-start data on
        // client partner connection (only fires once per connection lifetime).
        if (plcRunning && !conn.SafetyPlcRunning)
        {
            conn.SafetyPlcRunning = true;
            foreach (var other in ConnectionManager.ActiveConnections)
            {
                if (other != conn && other.IsSafety &&
                    other.OriginatorVendorId == conn.OriginatorVendorId &&
                    other.OriginatorSerialNumber == conn.OriginatorSerialNumber &&
                    !other.SafetyConsumerActive && !other.IsProducing)
                {
                    ProduceIoData(other);
                }
            }
        }
    }

    protected override void OnRemoteEndpointUpdated(IoConnection conn, IPEndPoint senderEp)
    {
        if (!conn.IsSafety) return;
        foreach (var other in ConnectionManager.ActiveConnections)
        {
            if (other != conn && other.IsSafety &&
                other.OriginatorVendorId == conn.OriginatorVendorId &&
                other.OriginatorSerialNumber == conn.OriginatorSerialNumber)
            {
                other.RemoteEndpoint = senderEp;
            }
        }
    }

    // ==================== Private ====================

    private void SendTimeCoordination(IoConnection conn)
    {
        var tcooBuf = new byte[6];
        // Use the same Stopwatch reference as ProduceIoData so our outgoing
        // data ts and outgoing TCOO ctv share one monotonic clock.
        long elapsedUs = (Stopwatch.GetTimestamp() - conn.SafetyProductionStartTicks)
            * 1_000_000 / Stopwatch.Frequency;
        ushort consumerTime = (ushort)((conn.SafetyInitialTimestamp + elapsedUs / 128) & 0xFFFF);

        bool isExtended = conn.SafetyFormat == 0x02;
        int len;
        if (isExtended)
        {
            len = SafetyFrameCodec.EncodeTimeCoordinationExtended(tcooBuf,
                conn.SafetyLastPingCount, consumerTime, conn.SafetyCidSeedS5);
        }
        else
        {
            len = SafetyFrameCodec.EncodeTimeCoordination(tcooBuf,
                conn.SafetyLastPingCount, consumerTime, conn.SafetyCidSeedS3);
        }

        SendUdpIoData(conn, tcooBuf.AsSpan(0, len));

        if (conn.SafetyStartupTraceUntilTicks > 0
            && Stopwatch.GetTimestamp() < conn.SafetyStartupTraceUntilTicks)
        {
            Console.WriteLine($"[SU-SEND-TCOO] conn={conn.ConnectionSerialNumber:X4} ctv={consumerTime} pingReply={conn.SafetyLastPingCount}");
        }
    }

    private void OnConnectionRemoved(IoConnection conn)
    {
        if (!conn.IsSafety) return;

        bool anySafetyLeft = false;
        foreach (var other in ConnectionManager.ActiveConnections)
        {
            if (other.IsSafety) { anySafetyLeft = true; break; }
        }

        if (!anySafetyLeft)
        {
            _supervisor.Scid = default;
            var svInst = _supervisor.CipClass.GetInstance(1);
            svInst?.GetAttribute(6)?.SetData(new byte[SafetyConfigurationId.Size]);
            svInst?.GetAttribute(25)?.SetData(new byte[UniqueNetworkId.Size]);
        }
    }

    private static int EstimateDataLength(int wireSize)
    {
        int shortDataLen = wireSize - 6;
        if (shortDataLen >= 1 && shortDataLen <= 2)
            return shortDataLen;

        int longDataLen = (wireSize - 8) / 2;
        if (longDataLen >= 3 && longDataLen <= 250 && longDataLen * 2 + 8 == wireSize)
            return longDataLen;

        return -1;
    }
}
