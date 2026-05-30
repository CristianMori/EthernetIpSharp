# SampleTag

Read & write Logix tags using `TagClient` (the symbol/tag service over EtherNet/IP). Demonstrates the structured-tag round-trip: browse → read → write → read-back.

## Run

```sh
# Default — read+write the "Amix" UDT on a PLC at 192.168.204.128
dotnet run --project samples/SampleTag

# Specific PLC and tag
dotnet run --project samples/SampleTag -- --plc=192.168.1.96 --tag=MyStruct

# Read only, skip the write step
dotnet run --project samples/SampleTag -- --no-write
```

## CLI options

| Flag | Meaning | Default |
|---|---|---|
| `--plc=<ip>` | PLC IP address | `192.168.204.128` |
| `--tag=<name>` | Tag name to read/write | `Amix` |
| `--no-write` | Read-only mode (skip the write step) | off |

## What the default tag expects

`Amix` is a UDT with these members:

| Member | Type |
|---|---|
| `bool1`, `bool2` | BOOL |
| `byte1`, `byte2` | SINT |
| `Int1`, `Int2` | INT |
| `Dint1` | DINT |
| `Lint1` | LINT |

If your PLC doesn't have an `Amix` tag, either create one with these members, or edit `Program.cs` to match your own UDT — the write-block calls `writer.Set<int>("Dint1", -999999)` etc, and those names need to match members of your structure.

## What you need on the other end

A Logix controller (real or emulated) with:
- TCP/IP comms enabled
- The target tag defined (controller-scope by default; for program-scope use `Program:Main.MyTag`)

## Atomic tag access

For simple atomic reads/writes without dealing with templates, use `TagClient.ReadAsync<T>` / `WriteAsync<T>` directly — see the README's *Logix tag client* section:

```csharp
await using var client = new TagClient("192.168.1.96");
await client.ConnectAsync();
int v = await client.ReadAsync<int>("MyDint");
await client.WriteAsync("MyBool", true);
```

Supported `T`: `bool`, `sbyte`/`byte`, `short`/`ushort`, `int`/`uint`, `long`/`ulong`, `float`, `double` — mapping to BOOL/SINT/INT/DINT/LINT/REAL/LREAL.
