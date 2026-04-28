using EipSim.Logix;

Console.WriteLine("=== TagClient → Real PLC (full browse) ===");

await using var client = new TagClient("192.168.204.128");
await client.ConnectAsync();

var result = await client.BrowseTagsAsync();

Console.WriteLine($"Tags: {result.Tags.Count} total, {result.UserTags.Count()} user");
Console.WriteLine($"Templates: {result.Templates.Count}\n");

foreach (var tag in result.UserTags)
{
    Console.WriteLine($"{tag}");
    if (tag.Template != null)
    {
        Console.WriteLine($"  [{tag.Template.StructureSize} bytes, {tag.Template.MemberCount} members]");
        foreach (var m in tag.Template.Members)
            Console.WriteLine($"    {m}");
    }
    Console.WriteLine();
}
