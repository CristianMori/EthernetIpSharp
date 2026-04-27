using System.Buffers.Binary;
using System.Net;

var file = File.ReadAllBytes(args[0]);
int pos = 0;
var packets = new List<(int num, byte[] data, int srcPort, int dstPort, string proto)>();
int pktNum = 0;

while (pos + 8 <= file.Length)
{
    uint blockType = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(pos));
    uint blockLen = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(pos + 4));
    if (blockLen < 12 || pos + (int)blockLen > file.Length) break;

    if (blockType == 6)
    {
        pktNum++;
        uint capturedLen = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(pos + 20));
        int dataStart = pos + 28;

        if (dataStart + (int)capturedLen <= file.Length && capturedLen > 54)
        {
            var pkt = file.AsSpan(dataStart, (int)capturedLen);
            int ipStart = 14;
            if (ipStart + 20 <= pkt.Length)
            {
                byte ipProto = pkt[ipStart + 9];
                int ipHdrLen = (pkt[ipStart] & 0x0F) * 4;
                int tStart = ipStart + ipHdrLen;

                if (tStart + 8 <= pkt.Length)
                {
                    int sp = BinaryPrimitives.ReadUInt16BigEndian(pkt.Slice(tStart));
                    int dp = BinaryPrimitives.ReadUInt16BigEndian(pkt.Slice(tStart + 2));

                    if (sp == 44818 || dp == 44818 || sp == 2222 || dp == 2222)
                    {
                        string proto = ipProto == 6 ? "TCP" : "UDP";
                        int payloadStart;
                        if (ipProto == 6)
                        {
                            int tcpHdrLen = ((pkt[tStart + 12] >> 4) & 0xF) * 4;
                            payloadStart = tStart + tcpHdrLen;
                        }
                        else
                            payloadStart = tStart + 8;

                        if (payloadStart < pkt.Length)
                        {
                            var payload = pkt.Slice(payloadStart).ToArray();
                            if (payload.Length > 0)
                                packets.Add((pktNum, payload, sp, dp, proto));
                        }
                    }
                }
            }
        }
    }
    pos += (int)((blockLen + 3) & ~3u);
}

Console.WriteLine($"Found {packets.Count} EIP packets\n");

foreach (var (num, data, sp, dp, proto) in packets)
{
    if (data.Length < 4) continue;
    string dir = (dp == 44818 || dp == 2222) ? "PLC->US" : "US->PLC";

    if (proto == "TCP" && data.Length >= 24)
    {
        ushort cmd = BinaryPrimitives.ReadUInt16LittleEndian(data);
        ushort len = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2));
        uint session = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4));
        uint status = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(8));

        string cmdName = cmd switch
        {
            0x0004 => "ListServices", 0x0063 => "ListIdentity",
            0x0065 => "RegisterSession", 0x0066 => "UnregisterSession",
            0x006F => "SendRRData", 0x0070 => "SendUnitData", _ => $"cmd0x{cmd:X4}"
        };

        Console.WriteLine($"#{num} {proto} {dir} | {cmdName} len={len} sess=0x{session:X8} stat={status}");

        if ((cmd == 0x006F) && data.Length > 30)
        {
            int cpfStart = 30;
            ushort itemCount = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(cpfStart));
            int ip2 = cpfStart + 2;

            for (int i = 0; i < itemCount && ip2 + 4 <= data.Length; i++)
            {
                ushort iType = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(ip2));
                ushort iLen = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(ip2 + 2));

                string tn = iType switch
                {
                    0x0000 => "NullAddr", 0x00B2 => "UnconnData",
                    0x8000 => "SockOT", 0x8001 => "SockTO", _ => $"type0x{iType:X4}"
                };

                Console.Write($"  CPF[{i}]: {tn} len={iLen}");

                if (iType == 0x00B2 && ip2 + 4 < data.Length)
                {
                    byte svc = data[ip2 + 4];
                    bool reply = (svc & 0x80) != 0;
                    byte sc = (byte)(svc & 0x7F);
                    string sn = sc switch
                    {
                        0x54 => "FwdOpen", 0x5B => "LargeFwdOpen", 0x4E => "FwdClose",
                        0x01 => "GetAttrAll", 0x0E => "GetAttrSingle",
                        _ => $"svc0x{sc:X2}"
                    };
                    Console.Write($" -> {(reply ? "REPLY" : "REQ")}:{sn}");
                    if (reply && ip2 + 4 + 3 < data.Length)
                        Console.Write($" gs=0x{data[ip2 + 6]:X2}");

                    // Hex dump of CIP payload
                    int dLen = Math.Min(iLen, 80);
                    Console.WriteLine();
                    Console.Write("    ");
                    for (int b = 0; b < dLen && ip2 + 4 + b < data.Length; b++)
                    {
                        Console.Write($"{data[ip2 + 4 + b]:X2} ");
                        if ((b + 1) % 16 == 0 && b + 1 < dLen) Console.Write("\n    ");
                    }
                }

                if ((iType == 0x8000 || iType == 0x8001) && ip2 + 4 + 8 <= data.Length)
                {
                    int port = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(ip2 + 6));
                    var ip = new IPAddress(data.AsSpan(ip2 + 8, 4));
                    Console.Write($" -> {ip}:{port}");
                }

                Console.WriteLine();
                ip2 += 4 + iLen;
            }
        }
    }
    else if (proto == "UDP" && data.Length >= 18)
    {
        ushort ic = BinaryPrimitives.ReadUInt16LittleEndian(data);
        if (ic == 2)
        {
            uint cid = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(6));
            uint seq = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(10));
            ushort dLen = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(16));
            Console.WriteLine($"#{num} {proto} {dir} | IO cid=0x{cid:X8} seq={seq} len={dLen}");
        }
    }
}
