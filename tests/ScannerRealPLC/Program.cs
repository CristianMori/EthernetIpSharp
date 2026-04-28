using EipSim.Logix;

Console.WriteLine("=== TagClient → Real PLC ===");
Console.WriteLine("Target: 192.168.204.128");

await using var client = new TagClient("192.168.204.128");
await client.ConnectAsync();
Console.WriteLine($"Connected. Session: 0x{client.SessionHandle:X8}");

// --- Browse Tags ---
Console.WriteLine("\n=== Browse Tags ===");
var tags = await client.BrowseTagsAsync();
foreach (var (name, symType) in tags)
{
    bool isStruct = (symType & 0x8000) != 0;
    bool isSystem = (symType & 0x1000) != 0;
    if (!isSystem && !name.StartsWith("__"))
        Console.WriteLine($"  {name}: type=0x{symType:X4} struct={isStruct}");
}
Console.WriteLine($"Total: {tags.Count} tags ({tags.Count(t => !t.Name.StartsWith("__") && (t.SymbolType & 0x1000) == 0)} user)");

// --- Read test:I (125 DINTs) ---
Console.WriteLine("\n=== Read 'test:I' (structure, 125 DINTs) ===");
try
{
    var data = await client.ReadTagRawAsync("test:I");
    ushort tagType = BitConverter.ToUInt16(data, 0);
    Console.WriteLine($"  tag_type=0x{tagType:X4}, data size={data.Length - 2} bytes");
    // First few DINTs
    for (int i = 0; i < Math.Min(5, (data.Length - 2) / 4); i++)
    {
        int val = BitConverter.ToInt32(data, 2 + i * 4);
        Console.WriteLine($"  Data[{i}] = {val}");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"  ERROR: {ex.Message}");
}

// --- Read test:O ---
Console.WriteLine("\n=== Read 'test:O' (structure, 124 DINTs) ===");
try
{
    var data = await client.ReadTagRawAsync("test:O");
    ushort tagType = BitConverter.ToUInt16(data, 0);
    Console.WriteLine($"  tag_type=0x{tagType:X4}, data size={data.Length - 2} bytes");
    for (int i = 0; i < Math.Min(5, (data.Length - 2) / 4); i++)
    {
        int val = BitConverter.ToInt32(data, 2 + i * 4);
        Console.WriteLine($"  Data[{i}] = {val}");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"  ERROR: {ex.Message}");
}

Console.WriteLine("\nDone.");
