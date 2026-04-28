using EipSim.Logix;

Console.WriteLine("=== TagClient String Test ===");

await using var client = new TagClient("192.168.204.128");
await client.ConnectAsync();

// Read AString
var strValue = await client.ReadStringAsync("AString");
Console.WriteLine($"AString = '{strValue}' (len={strValue.Length})");

// Read raw to see the structure
var raw = await client.ReadTagRawAsync("AString");
Console.Write("Raw bytes: ");
for (int i = 0; i < Math.Min(raw.Length, 30); i++)
    Console.Write($"{raw[i]:X2} ");
Console.WriteLine(raw.Length > 30 ? "..." : "");

Console.WriteLine("\nDone.");
