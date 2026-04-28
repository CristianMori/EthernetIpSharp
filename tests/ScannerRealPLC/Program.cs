using System.Buffers.Binary;
using EipSim.Logix;

Console.WriteLine("=== Multi-Tag Read/Write ===");

await using var client = new TagClient("192.168.204.128");
await client.ConnectAsync();

// --- Multi Read ---
Console.WriteLine("=== Read Multiple ===");
var values = await client.ReadMultipleAsync(["ADint", "AReal", "AString"]);
foreach (var (name, raw) in values)
{
    ushort tagType = BitConverter.ToUInt16(raw, 0);
    if (tagType == 0x00C4) // DINT
        Console.WriteLine($"  {name} = {BitConverter.ToInt32(raw, 2)} (DINT)");
    else if (tagType == 0x00CA) // REAL
        Console.WriteLine($"  {name} = {BitConverter.ToSingle(raw, 2)} (REAL)");
    else // structure (STRING etc)
        Console.WriteLine($"  {name} = [{raw.Length - 2} bytes] (type=0x{tagType:X4})");
}

// --- Multi Write ---
Console.WriteLine("\n=== Write Multiple ===");
var writeResults = await client.WriteMultipleAsync([
    ("ADint", LogixDataTypes.DINT, BitConverter.GetBytes(42)),
    ("AReal", LogixDataTypes.REAL, BitConverter.GetBytes(9.81f)),
]);
foreach (var (name, ok) in writeResults)
    Console.WriteLine($"  {name}: {(ok ? "OK" : "FAILED")}");

// --- Verify ---
Console.WriteLine("\n=== Verify ===");
var verify = await client.ReadMultipleAsync(["ADint", "AReal"]);
foreach (var (name, raw) in verify)
{
    ushort tagType = BitConverter.ToUInt16(raw, 0);
    if (tagType == 0x00C4)
        Console.WriteLine($"  {name} = {BitConverter.ToInt32(raw, 2)}");
    else if (tagType == 0x00CA)
        Console.WriteLine($"  {name} = {BitConverter.ToSingle(raw, 2)}");
}

Console.WriteLine("\nDone.");
