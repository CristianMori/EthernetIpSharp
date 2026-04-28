using EipSim.Logix;

Console.WriteLine("=== UDT Code Generation + Round-Trip Test ===");

await using var client = new TagClient("192.168.204.128");
await client.ConnectAsync();

var browse = await client.BrowseTagsAsync();
var mixTag = browse.Tags.First(t => t.Name.Equals("Amix", StringComparison.OrdinalIgnoreCase));
var template = mixTag.Template!;

// --- Generate code ---
Console.WriteLine("=== Generated Code for mixTypes ===\n");
string code = UdtCodeGenerator.Generate(template, "MyApp", "MixTypes");
Console.WriteLine(code);

// --- StructureValue round-trip ---
Console.WriteLine("\n=== StructureValue Write Test ===");

// Read current values
var before = await client.ReadStructAsync("Amix", template);
Console.WriteLine("Before:");
foreach (var (name, val) in before.ToDictionary())
    Console.WriteLine($"  {name} = {val}");

// Build new values
var writer = new StructureValue(template);
writer.SetBool("bool1", true);
writer.SetBool("bool2", false);
writer.Set<sbyte>("byte1", 99);
writer.Set<sbyte>("byte2", -1);
writer.Set<short>("Int1", 1000);
writer.Set<short>("Int2", 2000);
writer.Set<int>("Dint1", 123456);
writer.Set<long>("Lint1", 9876543210L);

// Write
await client.WriteStructValueAsync("Amix", writer);

// Read back
var after = await client.ReadStructAsync("Amix", template);
Console.WriteLine("\nAfter:");
foreach (var (name, val) in after.ToDictionary())
    Console.WriteLine($"  {name} = {val}");

Console.WriteLine("\nDone.");
