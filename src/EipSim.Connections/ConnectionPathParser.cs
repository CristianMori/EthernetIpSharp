using EipSim.Cip;

namespace EipSim.Connections;

/// <summary>
/// Parses the application path portion of a Forward Open connection path
/// to extract assembly instance IDs for config, O→T consumption, and T→O production.
/// </summary>
public readonly struct ConnectionPathResult
{
    public uint? ConfigAssemblyInstance { get; init; }
    public uint? ConsumedAssemblyInstance { get; init; }  // O→T
    public uint? ProducedAssemblyInstance { get; init; }  // T→O
    public bool HasElectronicKey { get; init; }
}

public static class ConnectionPathParser
{
    /// <summary>
    /// Parse the connection path from a Forward Open to extract assembly instances.
    /// Handles the common assembly shortcut: 20 04 24 xx 2C yy 2C zz
    /// (Class 0x04, Config instance xx, OT connection point yy, TO connection point zz)
    /// </summary>
    public static ConnectionPathResult Parse(ReadOnlySpan<byte> path, ForwardOpenRequest request)
    {
        // Strip FactoryTalk Logix Emulate wrapper if present.
        // Logix Emulate wraps Forward Open paths with: Class 0x04FC (21 00 FC 04) + ConnPoint 0x01 (2C 01)
        if (path.Length >= 6 &&
            path[0] == 0x21 && path[1] == 0x00 &&
            path[2] == 0xFC && path[3] == 0x04 &&
            path[4] == 0x2C && path[5] == 0x01)
        {
            path = path.Slice(6);
        }

        uint? configInst = null;
        uint? consumedInst = null;
        uint? producedInst = null;
        bool hasKey = false;

        // Collect all logical segments
        uint? currentClass = null;
        uint? currentInstance = null;
        var connectionPoints = new List<uint>();

        int offset = 0;
        while (offset < path.Length)
        {
            byte seg = path[offset];
            byte segType = (byte)(seg & 0xE0);

            if (segType == 0x20) // Logical segment
            {
                byte logicalType = (byte)(seg & 0x1C);
                byte format = (byte)(seg & 0x03);
                offset++;

                uint value;
                switch (format)
                {
                    case 0x00: // 8-bit
                        value = path[offset++];
                        break;
                    case 0x01: // 16-bit
                        if (offset % 2 != 0) offset++;
                        value = (uint)(path[offset] | (path[offset + 1] << 8));
                        offset += 2;
                        break;
                    default:
                        goto done;
                }

                switch (logicalType)
                {
                    case 0x00: // Class ID
                        currentClass = value;
                        break;
                    case 0x04: // Instance ID
                        currentInstance = value;
                        break;
                    case 0x0C: // Connection Point
                        connectionPoints.Add(value);
                        break;
                    case 0x10: // Attribute ID (skip)
                        break;
                }
            }
            else if (segType == 0x00 && (seg & 0x1F) == 0x00) // Port segment
            {
                // Skip port segments (routing info, not relevant for target)
                offset++;
                bool extended = (seg & 0x10) != 0;
                if (extended)
                {
                    byte addrSize = path[offset++];
                    offset += addrSize;
                    if (offset % 2 != 0) offset++; // pad
                }
                else
                {
                    offset++; // link address
                }
            }
            else if (seg == 0x34) // Electronic key segment
            {
                hasKey = true;
                // 0x34 (1 byte) + key format (1 byte) + key data (8 bytes) = 10 bytes
                offset += 10;
            }
            else if ((seg & 0xE0) == 0x80) // Data segment
            {
                offset++;
                byte dataSize = path[offset++];
                offset += dataSize * 2; // size in words
            }
            else if ((seg & 0xE0) == 0x40) // Network segment
            {
                offset++;
                offset++; // skip value
            }
            else
            {
                break; // Unknown segment, stop
            }
        }

        done:
        // Determine assembly instances based on connection points and the path
        // Common case: Assembly class (0x04), config instance, then connection points
        if (currentClass == 0x04 && currentInstance.HasValue)
        {
            if (connectionPoints.Count >= 2)
            {
                // 3 paths: config, O→T, T→O
                configInst = currentInstance.Value;
                consumedInst = connectionPoints[0]; // O→T
                producedInst = connectionPoints[1]; // T→O
            }
            else if (connectionPoints.Count == 1)
            {
                // Depends on which direction is non-null
                if (!request.OtoTParams.IsNull && !request.TtoOParams.IsNull)
                {
                    // Both non-null, single connection point = both O→T and T→O
                    consumedInst = connectionPoints[0];
                    producedInst = connectionPoints[0];
                }
                else if (!request.OtoTParams.IsNull)
                {
                    consumedInst = connectionPoints[0];
                }
                else
                {
                    producedInst = connectionPoints[0];
                }
            }
        }
        else if (connectionPoints.Count >= 2)
        {
            // No class specified explicitly, just connection points
            consumedInst = connectionPoints[0];
            producedInst = connectionPoints[1];
        }

        return new ConnectionPathResult
        {
            ConfigAssemblyInstance = configInst,
            ConsumedAssemblyInstance = consumedInst,
            ProducedAssemblyInstance = producedInst,
            HasElectronicKey = hasKey,
        };
    }
}
