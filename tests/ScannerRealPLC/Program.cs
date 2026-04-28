using EipSim.Logix;

Console.WriteLine("=== Read Entire UDT ===");

await using var client = new TagClient("192.168.204.128");
await client.ConnectAsync();

// Browse to get templates
var browse = await client.BrowseTagsAsync();

// Read CMoFramework
var fwTag = browse.Tags.First(t => t.Name.Contains("Framework"));
Console.WriteLine($"Tag: {fwTag.Name}");
Console.WriteLine($"Template: {fwTag.Template!.Name} ({fwTag.Template.StructureSize} bytes)\n");

var value = await client.ReadStructAsync(fwTag.Name, fwTag.Template);

// Show all members as a dictionary
Console.WriteLine("=== All Members ===");
foreach (var (name, val) in value.ToDictionary())
    Console.WriteLine($"  {name} = {val}");

// Typed access
Console.WriteLine("\n=== Typed Access ===");
Console.WriteLine($"  Tick100ms = {value.GetBool("Tick100ms")}");
Console.WriteLine($"  Tick1s = {value.GetBool("Tick1s")}");
Console.WriteLine($"  AlwaysTrue = {value.GetBool("AlwaysTrue")}");
Console.WriteLine($"  AlwaysFalse = {value.GetBool("AlwaysFalse")}");
Console.WriteLine($"  ApplicationCount = {value.Get<int>("ApplicationCount")}");
Console.WriteLine($"  Random = {value.Get<float>("Random")}");
Console.WriteLine($"  CycleTime = {value.Get<float>("CycleTime")}");
Console.WriteLine($"  InhibitAlarmGroups = [{string.Join(", ", value.GetArray<int>("InhibitAlarmGroups"))}]");

Console.WriteLine("\nDone.");
