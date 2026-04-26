using System.Buffers.Binary;

namespace EipSim.Connections;

/// <summary>
/// Parsed Forward Open request parameters (Vol1 Table 3-5.17).
/// </summary>
public readonly struct ForwardOpenRequest
{
    public byte PriorityTimeTick { get; init; }
    public byte TimeoutTicks { get; init; }
    public uint OtoTConnectionId { get; init; }
    public uint TtoOConnectionId { get; init; }
    public ushort ConnectionSerialNumber { get; init; }
    public ushort OriginatorVendorId { get; init; }
    public uint OriginatorSerialNumber { get; init; }
    public byte ConnectionTimeoutMultiplier { get; init; }
    public uint OtoTRpi { get; init; }
    public NetworkConnectionParams OtoTParams { get; init; }
    public uint TtoORpi { get; init; }
    public NetworkConnectionParams TtoOParams { get; init; }
    public byte TransportClassTrigger { get; init; }
    public byte ConnectionPathSizeWords { get; init; }
    public ReadOnlyMemory<byte> ConnectionPath { get; init; }

    public TransportClass TransportClass => (TransportClass)(TransportClassTrigger & 0x0F);
    public bool IsLargeForwardOpen { get; init; }

    /// <summary>Parse a Forward Open request from the service request data.</summary>
    public static ForwardOpenRequest Parse(ReadOnlySpan<byte> data, bool isLarge = false)
    {
        int offset = 0;

        byte priorityTimeTick = data[offset++];
        byte timeoutTicks = data[offset++];
        uint otConnId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
        uint toConnId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
        ushort connSerial = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
        ushort origVendor = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
        uint origSerial = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
        byte timeoutMult = data[offset++];
        offset += 3; // 3 reserved bytes

        uint otRpi = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;

        NetworkConnectionParams otParams;
        NetworkConnectionParams toParams;

        if (isLarge)
        {
            uint otParamsRaw = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
            otParams = NetworkConnectionParams.ParseLarge(otParamsRaw);
            uint toRpiVal = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
            uint toParamsRaw = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
            toParams = NetworkConnectionParams.ParseLarge(toParamsRaw);

            byte transportClassTrigger = data[offset++];
            byte pathSize = data[offset++];
            var path = data.Slice(offset, pathSize * 2).ToArray();

            return new ForwardOpenRequest
            {
                PriorityTimeTick = priorityTimeTick,
                TimeoutTicks = timeoutTicks,
                OtoTConnectionId = otConnId,
                TtoOConnectionId = toConnId,
                ConnectionSerialNumber = connSerial,
                OriginatorVendorId = origVendor,
                OriginatorSerialNumber = origSerial,
                ConnectionTimeoutMultiplier = timeoutMult,
                OtoTRpi = otRpi,
                OtoTParams = otParams,
                TtoORpi = toRpiVal,
                TtoOParams = toParams,
                TransportClassTrigger = transportClassTrigger,
                ConnectionPathSizeWords = pathSize,
                ConnectionPath = path,
                IsLargeForwardOpen = true,
            };
        }
        else
        {
            ushort otParamsRaw = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
            otParams = NetworkConnectionParams.Parse(otParamsRaw);
            uint toRpiVal = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)); offset += 4;
            ushort toParamsRaw = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset)); offset += 2;
            toParams = NetworkConnectionParams.Parse(toParamsRaw);

            byte transportClassTrigger = data[offset++];
            byte pathSize = data[offset++];
            var path = data.Slice(offset, pathSize * 2).ToArray();

            return new ForwardOpenRequest
            {
                PriorityTimeTick = priorityTimeTick,
                TimeoutTicks = timeoutTicks,
                OtoTConnectionId = otConnId,
                TtoOConnectionId = toConnId,
                ConnectionSerialNumber = connSerial,
                OriginatorVendorId = origVendor,
                OriginatorSerialNumber = origSerial,
                ConnectionTimeoutMultiplier = timeoutMult,
                OtoTRpi = otRpi,
                OtoTParams = otParams,
                TtoORpi = toRpiVal,
                TtoOParams = toParams,
                TransportClassTrigger = transportClassTrigger,
                ConnectionPathSizeWords = pathSize,
                ConnectionPath = path,
                IsLargeForwardOpen = false,
            };
        }
    }
}

/// <summary>
/// Parsed network connection parameters from Forward Open (Vol1 Table 3-5.8).
/// 16-bit: bit15=redundant_owner, bits14-13=conn_type, bits12-10=priority, bit9=fixed/variable, bits8-0=size
/// </summary>
public readonly struct NetworkConnectionParams
{
    public bool RedundantOwner { get; init; }
    public byte ConnectionType { get; init; }  // 0=Null, 1=Multicast, 2=Point-to-Point
    public byte Priority { get; init; }
    public bool IsVariable { get; init; }
    public ushort ConnectionSize { get; init; }

    public bool IsNull => ConnectionType == 0;

    public static NetworkConnectionParams Parse(ushort raw) => new()
    {
        RedundantOwner = (raw & 0x8000) != 0,
        ConnectionType = (byte)((raw >> 13) & 0x03),
        Priority = (byte)((raw >> 10) & 0x03),
        IsVariable = (raw & 0x0200) != 0,
        ConnectionSize = (ushort)(raw & 0x01FF),
    };

    public static NetworkConnectionParams ParseLarge(uint raw) => new()
    {
        RedundantOwner = (raw & 0x80000000) != 0,
        ConnectionType = (byte)((raw >> 29) & 0x03),
        Priority = (byte)((raw >> 26) & 0x03),
        IsVariable = (raw & 0x02000000) != 0,
        ConnectionSize = (ushort)(raw & 0xFFFF),
    };
}
