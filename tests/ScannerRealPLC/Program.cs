using EthernetIPSharp.Logix;

Console.WriteLine("=== Read AMix, Write, Read Back ===");

await using var client = new TagClient("192.168.204.128");
await client.ConnectAsync();

var browse = await client.BrowseTagsAsync();
var mixTag = browse.Tags.First(t => t.Name.Equals("Amix", StringComparison.OrdinalIgnoreCase));
var template = mixTag.Template!;

// Read current
var current = await client.ReadStructAsync("Amix", template);
Console.WriteLine("Current:");
foreach (var (name, val) in current.ToDictionary())
    Console.WriteLine($"  {name} = {val}");

// Write new values
Console.WriteLine("\nWriting new values...");
var writer = new StructureValue(template);
writer.SetBool("bool1", true);
writer.SetBool("bool2", true);
writer.Set<sbyte>("byte1", 77);
writer.Set<sbyte>("byte2", 88);
writer.Set<short>("Int1", -500);
writer.Set<short>("Int2", 32000);
writer.Set<int>("Dint1", -999999);
writer.Set<long>("Lint1", 1234567890123L);
await client.WriteStructValueAsync("Amix", writer);

// Read back
var after = await client.ReadStructAsync("Amix", template);
Console.WriteLine("\nAfter write:");
foreach (var (name, val) in after.ToDictionary())
    Console.WriteLine($"  {name} = {val}");

// Typed access
Console.WriteLine("\nTyped access:");
Console.WriteLine($"  bool1 = {after.GetBool("bool1")}");
Console.WriteLine($"  bool2 = {after.GetBool("bool2")}");
Console.WriteLine($"  byte1 = {after.Get<sbyte>("byte1")}");
Console.WriteLine($"  byte2 = {after.Get<sbyte>("byte2")}");
Console.WriteLine($"  Int1 = {after.Get<short>("Int1")}");
Console.WriteLine($"  Int2 = {after.Get<short>("Int2")}");
Console.WriteLine($"  Dint1 = {after.Get<int>("Dint1")}");
Console.WriteLine($"  Lint1 = {after.Get<long>("Lint1")}");

Console.WriteLine("\nDone.");
