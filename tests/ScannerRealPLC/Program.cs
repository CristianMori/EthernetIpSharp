using EipSim.Logix;

Console.WriteLine("=== TagClient → Real PLC ===");
Console.WriteLine("Target: 192.168.204.128");

await using var client = new TagClient("192.168.204.128");
await client.ConnectAsync();
Console.WriteLine($"Connected. Session: 0x{client.SessionHandle:X8}\n");

var result = await client.BrowseTagsAsync();

Console.WriteLine($"=== Tags ({result.Tags.Count} total, {result.UserTags.Count()} user) ===");
foreach (var tag in result.UserTags)
{
    Console.WriteLine($"  {tag}");
    if (tag.Template != null)
    {
        Console.WriteLine($"    Template: {tag.Template.Name} ({tag.Template.StructureSize} bytes)");
        foreach (var m in tag.Template.Members)
            Console.WriteLine($"      {m}");
    }
}

Console.WriteLine($"\n=== Templates ({result.Templates.Count}) ===");
foreach (var (id, tmpl) in result.Templates)
    Console.WriteLine($"  [{id}] {tmpl}");

Console.WriteLine("\nDone.");
