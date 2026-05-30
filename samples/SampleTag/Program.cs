// ============================================================================
// SampleTag — Read & write Logix tags via TagClient
// ============================================================================
//
// What this sample does:
//   Connects to a Logix controller, reads a structured tag, writes new values
//   into it, then reads the tag back to verify the write round-tripped
//   correctly. Uses TagClient (EthernetIPSharp.Logix) which speaks the
//   Logix-specific symbol/tag service over EtherNet/IP.
//
// The default tag "Amix" is a structure expected to contain these members:
//   bool1, bool2 : BOOL
//   byte1, byte2 : SINT
//   Int1, Int2   : INT
//   Dint1        : DINT
//   Lint1        : LINT
//
// Typical usage:
//   dotnet run --project samples/SampleTag
//   dotnet run --project samples/SampleTag -- --plc=192.168.1.96 --tag=MyStruct
//
// CLI options:
//   --plc=<ip>            PLC IP address. Default: 192.168.204.128
//   --tag=<name>          Tag name to read/write. Default: Amix
//   --no-write            Read-only mode (skip the write step)
//
// You can also write a different tag by changing the Amix members below to
// match your project's structure.
// ============================================================================

using EthernetIPSharp.Logix;

string GetArg(string key, string defaultValue)
{
    var match = args.FirstOrDefault(a => a.StartsWith($"--{key}=", StringComparison.OrdinalIgnoreCase));
    return match is null ? defaultValue : match[(match.IndexOf('=') + 1)..];
}
bool HasFlag(string key) =>
    args.Any(a => a.Equals($"--{key}", StringComparison.OrdinalIgnoreCase));

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------
string plcIp   = GetArg("plc", "192.168.204.128");
string tagName = GetArg("tag", "Amix");
bool   noWrite = HasFlag("no-write");

Console.WriteLine($"=== Logix Tag Scanner ===");
Console.WriteLine($"PLC: {plcIp}");
Console.WriteLine($"Tag: {tagName}");
Console.WriteLine($"Mode: {(noWrite ? "READ ONLY" : "READ / WRITE / READ-BACK")}");
Console.WriteLine();

// ----------------------------------------------------------------------------
// Connect — TagClient opens a TCP session and registers an EtherNet/IP session
// in its ConnectAsync() call.
// ----------------------------------------------------------------------------
await using var client = new TagClient(plcIp);
await client.ConnectAsync();

// ----------------------------------------------------------------------------
// Browse the controller's tag list so we can grab the structure template for
// the tag we want. The template tells us field names, types, and offsets.
// ----------------------------------------------------------------------------
var browse = await client.BrowseTagsAsync();
var tag = browse.Tags.FirstOrDefault(t => t.Name.Equals(tagName, StringComparison.OrdinalIgnoreCase))
    ?? throw new InvalidOperationException($"Tag '{tagName}' not found on controller");
var template = tag.Template
    ?? throw new InvalidOperationException($"Tag '{tagName}' is not a structure (no template)");

// ----------------------------------------------------------------------------
// Step 1: Read current value
// ----------------------------------------------------------------------------
var current = await client.ReadStructAsync(tagName, template);
Console.WriteLine("Current:");
foreach (var (name, val) in current.ToDictionary())
    Console.WriteLine($"  {name} = {val}");

if (noWrite)
{
    Console.WriteLine("\nDone (read-only).");
    return;
}

// ----------------------------------------------------------------------------
// Step 2: Build a StructureValue with new field values and write it
// ----------------------------------------------------------------------------
Console.WriteLine("\nWriting new values...");
var writer = new StructureValue(template);
// The names below must match members of the tag's UDT. Edit these to match
// your own structure if you're using a different tag.
writer.SetBool("bool1", true);
writer.SetBool("bool2", true);
writer.Set<sbyte>("byte1", 77);
writer.Set<sbyte>("byte2", 88);
writer.Set<short>("Int1", -500);
writer.Set<short>("Int2", 32000);
writer.Set<int>("Dint1", -999999);
writer.Set<long>("Lint1", 1234567890123L);
await client.WriteStructValueAsync(tagName, writer);

// ----------------------------------------------------------------------------
// Step 3: Read back & verify
// ----------------------------------------------------------------------------
var after = await client.ReadStructAsync(tagName, template);
Console.WriteLine("\nAfter write:");
foreach (var (name, val) in after.ToDictionary())
    Console.WriteLine($"  {name} = {val}");

// ----------------------------------------------------------------------------
// Step 4: Typed accessors — read individual fields back with strong typing
// ----------------------------------------------------------------------------
Console.WriteLine("\nTyped access:");
Console.WriteLine($"  bool1 = {after.GetBool("bool1")}");
Console.WriteLine($"  bool2 = {after.GetBool("bool2")}");
Console.WriteLine($"  byte1 = {after.Get<sbyte>("byte1")}");
Console.WriteLine($"  byte2 = {after.Get<sbyte>("byte2")}");
Console.WriteLine($"  Int1  = {after.Get<short>("Int1")}");
Console.WriteLine($"  Int2  = {after.Get<short>("Int2")}");
Console.WriteLine($"  Dint1 = {after.Get<int>("Dint1")}");
Console.WriteLine($"  Lint1 = {after.Get<long>("Lint1")}");

Console.WriteLine("\nDone.");
