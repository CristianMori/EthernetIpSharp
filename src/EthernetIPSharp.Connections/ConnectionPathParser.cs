using EthernetIPSharp.Cip;

namespace EthernetIPSharp.Connections;

/// <summary>
/// Result of parsing a Forward Open connection path.
/// Contains the assembly instance IDs for config, O→T consumption, and T→O production.
/// </summary>
public readonly struct ConnectionPathResult
{
    /// <summary>Configuration assembly instance ID, or null if not specified.</summary>
    public uint? ConfigAssemblyInstance { get; init; }

    /// <summary>O→T consumed assembly instance (what the scanner sends to us), or null.</summary>
    public uint? ConsumedAssemblyInstance { get; init; }

    /// <summary>T→O produced assembly instance (what we send to the scanner), or null.</summary>
    public uint? ProducedAssemblyInstance { get; init; }

    /// <summary>True if the path contained an electronic key segment.</summary>
    public bool HasElectronicKey { get; init; }
}

/// <summary>
/// Parses the application path portion of a Forward Open connection path
/// to extract assembly instance IDs for config, O→T consumption, and T→O production.
///
/// Handles:
/// - Logix Emulate wrapper (class 0x04FC + connection point 0x01) — stripped automatically
/// - Electronic key segments (0x34) — skipped
/// - Assembly shortcut format: 20 04 24 xx 2C yy 2C zz
/// - Port, data, and network segments — skipped
/// </summary>
public static class ConnectionPathParser
{
    /// <summary>Maximum number of connection points expected in a path.</summary>
    private const int MaxConnectionPoints = 4;

    /// <summary>
    /// Parse the connection path from a Forward Open to extract assembly instances.
    /// Handles the common assembly shortcut: 20 04 24 xx 2C yy 2C zz
    /// (Class 0x04, Config instance xx, OT connection point yy, TO connection point zz).
    /// Resilient to malformed/truncated paths — returns what it can parse.
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

        uint? currentClass = null;
        uint? currentInstance = null;

        // Use fixed buffer instead of List to avoid allocation
        Span<uint> connectionPoints = stackalloc uint[MaxConnectionPoints];
        int connPointCount = 0;

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
                        if (offset >= path.Length) goto done;
                        value = path[offset++];
                        break;
                    case 0x01: // 16-bit
                        if (offset % 2 != 0) offset++; // pad to word boundary
                        if (offset + 2 > path.Length) goto done;
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
                        if (connPointCount < MaxConnectionPoints)
                            connectionPoints[connPointCount++] = value;
                        break;
                    case 0x10: // Attribute ID — skip
                        break;
                }
            }
            else if (segType == 0x00) // Port segment (any port number in low bits)
            {
                // Skip port segments — routing info, not relevant for target
                bool extended = (seg & 0x10) != 0;
                offset++;
                if (extended)
                {
                    if (offset >= path.Length) goto done;
                    byte addrSize = path[offset++];
                    offset += addrSize;
                    if (offset % 2 != 0) offset++; // pad
                }
                else
                {
                    if (offset >= path.Length) goto done;
                    offset++; // link address
                }
            }
            else if (seg == 0x34) // Electronic key segment
            {
                hasKey = true;
                // Format: 0x34 (1) + key_format (1) + key_data (variable, typically 8 bytes for format 4/5)
                offset++; // skip 0x34
                if (offset >= path.Length) goto done;
                byte keyFormat = path[offset++];
                // Format 4 and 5 both use 8 bytes of key data
                int keyDataSize = (keyFormat == 4 || keyFormat == 5) ? 8 : 0;
                offset += keyDataSize;
            }
            else if (segType == 0x80) // Data segment
            {
                offset++; // segment byte
                if (offset >= path.Length) goto done;
                byte dataSize = path[offset++]; // size in words
                offset += dataSize * 2;
            }
            else if (segType == 0x40) // Network segment
            {
                offset++; // segment byte
                if (offset >= path.Length) goto done;
                offset++; // skip value
            }
            else
            {
                break; // Unknown segment, stop
            }
        }

        done:
        // Determine assembly instances based on connection points and the path.
        // Common case: Assembly class (0x04), config instance, then connection points.
        if (currentClass == 0x04 && currentInstance.HasValue)
        {
            if (connPointCount >= 2)
            {
                configInst = currentInstance.Value;
                consumedInst = connectionPoints[0]; // O→T
                producedInst = connectionPoints[1]; // T→O
            }
            else if (connPointCount == 1)
            {
                // Single connection point — depends on which direction is non-null
                if (!request.OtoTParams.IsNull && !request.TtoOParams.IsNull)
                {
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
        else if (connPointCount >= 2)
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
