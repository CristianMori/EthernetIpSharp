using EipSim.Logix;

Console.WriteLine("=== TagClient String Write Test ===");

await using var client = new TagClient("192.168.204.128");
await client.ConnectAsync();

// Read current value
var before = await client.ReadStringAsync("AString");
Console.WriteLine($"Before: '{before}'");

// Browse to get the STRING structure handle
var result = await client.BrowseTagsAsync();
var aStringTag = result.Tags.First(t => t.Name == "AString");
ushort structHandle = aStringTag.Template!.StructureHandle;
Console.WriteLine($"Structure handle: 0x{structHandle:X4}");

// Write new value
await client.WriteStringAsync("AString", "Cristian is a genius!", structHandle);
Console.WriteLine("Wrote: 'Cristian is a genius!'");

// Read back
var after = await client.ReadStringAsync("AString");
Console.WriteLine($"Read back: '{after}'");

Console.WriteLine("\nDone.");
