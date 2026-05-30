# EthernetIPSharp Samples

Five runnable samples that demonstrate using EthernetIPSharp as either an
EtherNet/IP **adapter** (target / I/O slave) or an EtherNet/IP **scanner**
(originator / I/O master), with and without CIP Safety.

| Sample | Role | Safety | What it does |
|---|---|---|---|
| [`SafetyAdapterSample`](SafetyAdapterSample/) | Target | Yes | CIP Safety adapter — accepts safety connections from a PLC or compatible scanner |
| [`StandardAdapterSample`](StandardAdapterSample/) | Target | No | Generic EtherNet/IP I/O adapter — compatible with Studio 5000 "Generic Ethernet Module" |
| [`CipEchoServer`](CipEchoServer/) | Target | No | Catch-all CIP server. Logs any unhandled request (any service / class / instance / attribute) and optionally returns N bytes of incremental data. Handles UCMM + Class 3 from Logix MSG instructions. |
| [`SampleStandardScanner`](SampleStandardScanner/) | Scanner | No | Opens a Class 1 I/O connection to a target adapter and exchanges data cyclically |
| [`SampleTag`](SampleTag/) | Client | No | Reads & writes a Logix structured tag (explicit messaging) |
| [`SampleSafetyScanner`](SampleSafetyScanner/) | Scanner | Yes | Opens a CIP Safety connection pair to a 1734 safety I/O module |

## Running

All samples run with `dotnet run --project samples/<name>`. CLI options use
`--key=value` form — see the comment block at the top of each `Program.cs` for
the full list.

```sh
# Safety adapter, default (test2 profile, binds 192.168.204.1)
dotnet run --project samples/SafetyAdapterSample

# Safety adapter, real PLC profile (binds 192.168.1.84)
dotnet run --project samples/SafetyAdapterSample -- --profile=plc

# Safety adapter, custom IP and identity
dotnet run --project samples/SafetyAdapterSample -- \
    --bind=10.0.0.5 --vendor=12 --snn=4D90_0101_A35C --node=0x0A000005

# Catch-all CIP echo server — listens on TCP 44819, returns 20 bytes (0..19)
#   for every unhandled request. Use any non-44818 port if your PLC's
#   I/O module already targets the standard port.
dotnet run --project samples/CipEchoServer -- 0.0.0.0 44819 20

# Standard adapter — default config matches Studio 5000 Generic Ethernet Module
dotnet run --project samples/StandardAdapterSample

# Standard adapter, custom bind & assemblies
dotnet run --project samples/StandardAdapterSample -- \
    --bind=192.168.1.84 --asm-input=100 --input-bytes=500

# Standard scanner — defaults match StandardAdapterSample (great for end-to-end test)
#   Terminal 1: dotnet run --project samples/StandardAdapterSample
#   Terminal 2: dotnet run --project samples/SampleStandardScanner -- --target=127.0.0.1
dotnet run --project samples/SampleStandardScanner -- --target=192.168.1.84

# Read/write a Logix tag (default tag = Amix, default PLC = 192.168.204.128)
dotnet run --project samples/SampleTag -- --plc=192.168.1.96 --tag=MyTag

# Read-only mode
dotnet run --project samples/SampleTag -- --no-write

# Safety scanner targeting a 1734-IB8S in slot 1 behind 1734-ENT at .76
dotnet run --project samples/SampleSafetyScanner -- --target=192.168.1.76 --slot=1
```

## What you need on the other end

- **SafetyAdapterSample** — A safety scanner: a real ControlLogix with a
  safety I/O module configured as `ETHERNET-MODULE` targeting your adapter's
  IP, or a compatible Logix emulator. You'll need a matching SNN, electronic
  key, and SCID — they come from your scanner's project file.

- **StandardAdapterSample** — Any EtherNet/IP scanner. In Studio 5000, add
  the adapter as a "Generic Ethernet Module" with Data-DINT format, Input
  Assembly = 100 (size 125), Output Assembly = 102 (size 124), Config = 105
  (size 10). The defaults in the sample match these.

- **CipEchoServer** — Any client that sends explicit CIP. A Logix MSG
  instruction works well: set the Path to this server's IP (must NOT be the
  port your PLC's I/O module is already using), pick any service code +
  class + instance + attribute, and the server will print the request and
  return whatever payload size you configured. Both `CIP Generic` MSG (UCMM)
  and `Connected` MSG (Class 3) flows are supported. See
  [`CipEchoServer/Program.cs`](CipEchoServer/Program.cs) for the
  `CatchAllDispatcher` callback pattern.

- **SampleStandardScanner** — Any non-safety EtherNet/IP target adapter that
  exposes Class 1 I/O assemblies. Defaults are sized to talk to a
  `StandardAdapterSample` instance on the same machine for a self-contained
  loopback test; point `--target` at a real adapter's IP for hardware tests.

- **SampleTag** — A Logix controller with the target tag defined. The default
  tag `Amix` is a structure with fields `bool1`/`bool2` (BOOL), `byte1`/`byte2`
  (SINT), `Int1`/`Int2` (INT), `Dint1` (DINT), `Lint1` (LINT). Adjust the
  writer block in `Program.cs` to match your own structure.

- **SampleSafetyScanner** — A real 1734-IB8S safety input module sitting in
  the backplane of a 1734-ENT EtherNet/IP adapter. The identity values
  (SNN, SCCRC, SCTS, electronic key) in the sample are device-specific and
  may need to be captured from a working scanner session against your
  specific hardware.

## Network binding

The adapter samples bind to a specific local IP. The IP must already be
assigned to a NIC on the host machine. To add a secondary IP on Windows:

```cmd
netsh interface ip add address "Ethernet" 192.168.1.84 255.255.255.0
```

The scanner samples connect outbound — no local bind setup needed.
