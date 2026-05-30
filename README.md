# EthernetIPSharp

A complete EtherNet/IP and CIP Safety protocol stack written in C# (.NET 8). Acts as **adapter** (target / I/O slave), **scanner** (originator / I/O master), or **Logix-compatible tag server / client** — with or without CIP Safety. Tested against real Allen-Bradley ControlLogix and CompactLogix PLCs as well as 1734 distributed safety I/O modules.

The library is layered into independent projects so you can use only the parts you need: bring in `EthernetIPSharp.Cip` if you just want a CIP message router, add `EthernetIPSharp.Device` for I/O assemblies, layer on `EthernetIPSharp.Safety` if you need a SIL-3-style safety connection, or use `EthernetIPSharp.Logix` for symbolic tag access against a real PLC.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Project layout](#project-layout)
- [Quick start](#quick-start)
  - [Standard adapter (Generic Ethernet Module)](#standard-adapter-generic-ethernet-module)
  - [CIP Safety adapter](#cip-safety-adapter)
  - [Standard I/O scanner](#standard-io-scanner)
  - [CIP Safety scanner](#cip-safety-scanner)
  - [Logix tag client](#logix-tag-client)
  - [Logix tag server](#logix-tag-server)
- [Samples](#samples)
- [Building and testing](#building-and-testing)
- [Library reference](#library-reference)
- [CIP services supported](#cip-services-supported)
- [CIP Safety details](#cip-safety-details)
- [Known limitations](#known-limitations)
- [License](#license)

---

## Features

**Standard EtherNet/IP**
- TCP encapsulation (port 44818) — `RegisterSession`, `SendRRData`, `SendUnitData`, `UnregisterSession`, `ListIdentity`, `ListServices`, `ListInterfaces`
- UDP I/O transport (port 2222) — Class 0 and Class 1 implicit messaging
- Forward Open / Large Forward Open / Forward Close with full parameter parsing
- Run/Idle header handling on Class 1 connections
- CIP Identity, Assembly, Connection Manager, TCP/IP Interface, and Ethernet Link objects pre-registered
- Dedicated high-priority production thread per connection with high-resolution timer; alloc-free hot path

**CIP Safety (originator and target)**
- Base Format and Extended Format safety frames (short and long variants)
- Connection Parameter CRC (CPCRC) computation and validation
- Safety Network Segment parser/encoder
- Time Coordination (TCOO) message exchange and ping cycle
- Forward-only timestamp guard (the producer's outgoing timestamp never goes backward, even when consumer-time correction would normally cause it to)
- Safety Supervisor and Safety Validator CIP objects
- Configuration Identifier (SCCRC + SCTS) handling
- Interop-tested against Allen-Bradley ControlLogix as originator and 1734-IB8S as target

**Logix tag protocol**
- `Read Tag` (0x4C), `Write Tag` (0x4D), Fragmented variants (0x52/0x53), `Read Modify Write` (0x4E)
- `Multiple Service Packet` (0x0A) for batched explicit messages
- Tag browsing via `Get Instance Attribute List` (0x55) — paginated
- UDT template queries and structure read/write
- `TagClient` for connecting to a real PLC and reading/writing tags by name

**Diagnostics**
- Connection lifecycle events
- Per-frame send/receive counters
- Heavy in-source comments explaining wire formats and edge cases

---

## Architecture

The codebase is split into small, focused projects with one-way dependencies:

```
                         ┌────────────────────────┐
                         │ EthernetIPSharp.Cip    │
                         │ (pure protocol)        │
                         └───────────┬────────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
┌───────────▼──────────┐  ┌──────────▼──────────┐  ┌──────────▼──────────┐
│ EthernetIPSharp.     │  │ EthernetIPSharp.    │  │ EthernetIPSharp.    │
│ Protocol             │  │ Connections         │  │ Logix               │
│ (TCP/UDP sockets)    │  │ (Forward Open/Close)│  │ (tag client/server) │
└───────────┬──────────┘  └──────────┬──────────┘  └─────────────────────┘
            │                        │
            └────────────┬───────────┘
                         │
              ┌──────────▼──────────┐
              │ EthernetIPSharp.    │
              │ Device              │
              │ (VirtualDevice,     │
              │  StandardDevice)    │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │ EthernetIPSharp.    │
              │ Safety              │
              │ (SafetyDevice, CRCs,│
              │  TCOO, validators)  │
              └─────────────────────┘
```

- **`EthernetIPSharp.Cip`** — Pure CIP: paths + `PathBuilder`, services, `CipDispatcher` + `CatchAllDispatcher`, encapsulation header, CPF, identity. No sockets.
- **`EthernetIPSharp.Protocol`** — Sockets only: `EipAdapter` (Class-3-clean TCP listener), `IoEipAdapter` (subclass adding Sockaddr Info for Class 0/1 I/O), `EipScanner` + `ConnectedExplicit` (TCP client + Class 3 explicit messaging), `EipUdpTransport` (UDP I/O).
- **`EthernetIPSharp.Connections`** — Forward Open/Close parsing and connection lifecycle, used by both adapter and scanner.
- **`EthernetIPSharp.Device`** — `VirtualDevice` (abstract base) + `StandardDevice` (non-safety I/O). Ties dispatcher + assemblies + I/O transport together.
- **`EthernetIPSharp.Safety`** — `SafetyDevice` (extends `VirtualDevice` with safety framing), CRC routines, TCOO logic, Safety Supervisor/Validator objects, plus `SafetyScannerConnection` for the originator side.
- **`EthernetIPSharp.Logix`** — `LogixDispatcher` (server side: serves tags), `TagClient` (client side: reads/writes tags on a real PLC), tag database with change events, UDT templates.

---

## Project layout

```
src/
  EthernetIPSharp.Cip/           Core CIP protocol (no I/O dependencies)
  EthernetIPSharp.Protocol/      TCP/UDP transport (adapter + scanner)
  EthernetIPSharp.Connections/   Forward Open/Close, connection lifecycle
  EthernetIPSharp.Device/        Virtual device composition (VirtualDevice, StandardDevice)
  EthernetIPSharp.Safety/        CIP Safety: framing, CRCs, TCOO, validators
  EthernetIPSharp.Logix/         Logix tag client & server, UDT templates
  EthernetIPSharp.Host/          Console host (used during development; samples cover this now)

samples/
  SafetyAdapterSample/           CIP Safety adapter — runs against a real PLC or compatible emulator
  StandardAdapterSample/         Plain EtherNet/IP adapter — Studio 5000 Generic Ethernet Module
  CipEchoServer/                 Catch-all CIP server — captures any unhandled request (UCMM or Class 3) and returns N bytes of incremental data
  SampleStandardScanner/         Class 1 I/O scanner that connects to a target adapter
  SampleTag/                     Logix tag reader/writer (explicit messaging, TagClient)
  SampleSafetyScanner/           CIP Safety originator targeting a 1734 safety I/O module

tests/
  EthernetIPSharp.Cip.Tests/         CIP path parsing, MR codec, service registration
  EthernetIPSharp.Connections.Tests/ Forward Open parameter parsing
  EthernetIPSharp.Protocol.Tests/    Encapsulation, scanner ↔ adapter loopback
  EthernetIPSharp.Logix.Tests/       Tag database, read/write, edge cases
  EthernetIPSharp.Safety.Tests/      CRC check values, frame codec round-trips, segment parser
  CipMessageSniffer/                 Offline TCP+UDP CIP message decoder
  LogixHost/                         Stand-alone Logix tag server for pycomm3 integration tests
  pycomm3_test.py                    Python-side pycomm3 compatibility test
```

---

## Quick start

### Standard adapter (Generic Ethernet Module)

```csharp
using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Device;

var identity = new IdentityInfo
{
    VendorId      = 0x0001,
    DeviceType    = 0x000C,    // Communications Adapter
    ProductCode   = 1,
    MajorRevision = 1,
    MinorRevision = 0,
    SerialNumber  = 0xC0FFEE42,
    ProductName   = "My Simulator",
};

await using var device = new StandardDevice(identity, IPAddress.Parse("192.168.1.100"));

// Matches Studio 5000 "Generic Ethernet Module" with Comm Format = Data - DINT
device.AddAssembly(100, 500, "T->O Input (125 DINTs)");
device.AddAssembly(102, 496, "O->T Output (124 DINTs)");
device.AddAssembly(105,  10, "Configuration");

await device.StartAsync();

// Update produced data — the PLC will see this in its Input tag
device.Assemblies.GetAssembly(100)!.Write(0, 42);

// Read what the PLC sent us — its Output tag
int plcOutputDint0 = device.Assemblies.GetAssembly(102)!.Read<int>(0);
```

### CIP Safety adapter

```csharp
using System.Net;
using EthernetIPSharp.Cip;
using EthernetIPSharp.Safety;

var identity = new IdentityInfo
{
    VendorId      = 1, DeviceType = 0, ProductCode = 26,
    MajorRevision = 1, MinorRevision = 1,
    SerialNumber  = 0xC0FFEE42,
    ProductName   = "My Safety Module",
};

// Safety Network Number (12 hex chars displayed BE, stored LE on the wire)
var snn = new SafetyNetworkNumber(new byte[] { 0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D });

// Safety node address = your IP packed BE as uint32
uint nodeAddress = 0xC0A80154;   // 192.168.1.84

await using var device = new SafetyDevice(
    identity, IPAddress.Parse("192.168.1.84"), snn, nodeAddress);

// 1-byte safety data assemblies + a 0-byte config assembly
device.AddAssembly(  1, 1, "Safety Data In");
device.AddAssembly(199, 1, "Safety Data Out");
device.AddAssembly(199, 0, "Configuration");

await device.StartAsync();
device.Assemblies.GetAssembly(1)!.Write<byte>(0, 0x42);
```

### Standard I/O scanner

```csharp
using System.Net;
using EthernetIPSharp.Protocol;

await using var scanner = new EipScanner();
await scanner.ConnectAsync(IPAddress.Parse("192.168.1.84"));

var udp = new EipUdpTransport(new IPEndPoint(IPAddress.Any, 2222));
await udp.StartAsync(CancellationToken.None);

var conn = await scanner.ForwardOpenAsync(new ForwardOpenConfig
{
    ConsumedAssembly = 102, ProducedAssembly = 100, ConfigAssembly = 105,
    ConsumedSize     = 496, ProducedSize     = 500,
    Rpi              = 10_000,        // 10 ms
    TransportClass   = 1,             // Class 1 cyclic
    TimeoutMultiplier = 2,            // x16
});

conn.DataReceived += data => Console.WriteLine($"Got {data.Length} bytes");
conn.Write(0, 1234);                   // What target reads as input
int received = conn.Read<int>(0);      // What target produced

await conn.CloseAsync();
```

### CIP Safety scanner

See `samples/SampleSafetyScanner/Program.cs` for a worked example against a 1734-IB8S safety input module behind a 1734-ENT EtherNet/IP adapter. The originator side requires:

- Originator identity + Safety Network Number (UNID)
- Target identity (TUNID) — the SNN burned into the safety module
- Safety Configuration Identifier (SCCRC + SCTS) — proves you have the right config
- Electronic key for the target module
- Route prefix (e.g. backplane port + slot)
- Server and Client `SafetyForwardOpenConfig` — RPIs, ping interval multipliers, timeout multipliers

```csharp
var conn = await SafetyScannerConnection.OpenAsync(
    scanner, udp, serverConfig, clientConfig,
    originatorVendorId, originatorSerial,
    routePrefix, serverAppPath, clientAppPath);

conn.SetOutputData(new byte[] { 0x00 });   // safe state
conn.DataReceived += data => /* ... */;
```

### Logix tag client

```csharp
using EthernetIPSharp.Logix;

await using var client = new TagClient("192.168.1.96");
await client.ConnectAsync();

// Read & write simple atomic tags
int rate = await client.ReadAsync<int>("rate");
await client.WriteAsync("rate", 1500);

// Read a structured tag by template
var browse = await client.BrowseTagsAsync();
var tag = browse.Tags.First(t => t.Name == "MyUdt");
var value = await client.ReadStructAsync("MyUdt", tag.Template!);

foreach (var (name, val) in value.ToDictionary())
    Console.WriteLine($"{name} = {val}");

// Write a structure
var writer = new StructureValue(tag.Template!);
writer.SetBool("enable", true);
writer.Set<int>("setpoint", 100);
await client.WriteStructValueAsync("MyUdt", writer);
```

### Logix tag server

```csharp
var logix = new LogixDispatcher();

logix.Tags.AddTag("rate", LogixDataTypes.DINT).Write(0, 1500);
logix.Tags.AddTag("temperature", LogixDataTypes.REAL).Write(0, 72.5f);
logix.Tags.AddTag("counts", LogixDataTypes.INT, elementCount: 100);

// React to client writes
logix.Tags.FindByName("rate")!.ValueChanged += (tag, change) =>
    Console.WriteLine($"rate = {tag.Read<int>()}");

var identity = new IdentityInfo { /* ... */ };
var adapter = new EipAdapter(logix, identity);
await adapter.ListenAsync(IPAddress.Any, 44818);
```

---

## Samples

Six runnable console apps under `samples/`. Each one has a header comment block listing every CLI option. See [`samples/README.md`](samples/README.md) for a quick overview and end-to-end usage examples.

| Sample | Role | Safety | Brief |
|---|---|---|---|
| `SafetyAdapterSample` | Target | Yes | CIP Safety adapter. Two profiles (`test2`, `plc`) or fully custom via CLI |
| `StandardAdapterSample` | Target | No | Plain EtherNet/IP adapter compatible with Studio 5000 Generic Ethernet Module |
| `CipEchoServer` | Target | No | Catch-all CIP server — logs any unhandled request and optionally returns N bytes of incremental data. Handles UCMM + Class 3 from Logix MSG instructions. |
| `SampleStandardScanner` | Scanner | No | Class 1 I/O scanner — opens a cyclic connection to a target adapter |
| `SampleTag` | Client | No | Logix tag reader/writer (explicit messaging) |
| `SampleSafetyScanner` | Scanner | Yes | CIP Safety originator targeting a 1734 safety I/O module |

Run any sample with:

```bash
dotnet run --project samples/<name>
dotnet run --project samples/<name> -- --key=value [...]
```

Defaults are set up so `SampleStandardScanner` can talk to `StandardAdapterSample` on the same machine (loopback) without any wiring:

```bash
# Terminal 1
dotnet run --project samples/StandardAdapterSample

# Terminal 2
dotnet run --project samples/SampleStandardScanner -- --target=127.0.0.1
```

---

## Building and testing

```bash
# Build everything
dotnet build EthernetIPSharp.slnx

# Run the unit test suite
dotnet test EthernetIPSharp.slnx

# Run a single project's tests
dotnet test tests/EthernetIPSharp.Safety.Tests
```

Requirements: .NET 8 SDK or newer.

The test suite covers CIP path parsing, MR codec, encapsulation, scanner ↔ adapter loopback, tag read/write/browse, CRC check values, safety frame round-trips, and safety segment parsing.

---

## Library reference

### `EthernetIPSharp.Cip`

| Type | What it is |
|---|---|
| `CipDispatcher` | Routes service requests through the class → instance → attribute tree. `OnUnhandled` is a virtual catch-all hook called for every unmatched path. |
| `CatchAllDispatcher` | `CipDispatcher` subclass that routes every unmatched request through a single `Handler` lambda — `(in CatchAllRequest) -> CatchAllReply`. Useful for echo servers / sniffers without subclassing. |
| `CipClass`, `CipInstance`, `CipAttribute` | CIP object model |
| `CipPath`, `PathBuilder` | EPATH parser (logical + symbolic + electronic key segments) and a helper for building logical EPATHs from class/instance/attribute/element fields. |
| `MrCodec` | Message Router request/response binary codec |
| `EncapsulationHeader` | 24-byte TCP framing |
| `CpfParser`, `CpfItem` | Common Packet Format |
| `IdentityInfo` | Strongly-typed device identity (vendor/serial/product/etc.) |
| `CipDataType`, `CipDataSerializer` | Wire-format type IDs and (de)serialization |
| `CipStatus` | All general-status codes |

### `EthernetIPSharp.Protocol`

| Type | What it is |
|---|---|
| `EipAdapter` | TCP listener (port 44818). Hosts an `ICipDispatch`. Class-3-clean by default (no Sockaddr Info on Forward Open replies); has a `ConnectionIdLookup` hook for SendUnitData OT→TO translation. |
| `IoEipAdapter` | `EipAdapter` subclass that attaches Sockaddr Info O→T / T→O items on Class 0/1 Forward Open replies and fires `ConnectionOpened`. Used by `VirtualDevice` / `StandardDevice`. |
| `EipScanner` | TCP client. RegisterSession + `SendExplicitAsync` (UCMM) + `OpenExplicitAsync` (Class 3 connected explicit) + `ForwardOpenAsync` (Class 0/1 I/O) |
| `ConnectedExplicit` | Class 3 connected explicit messaging handle returned by `EipScanner.OpenExplicitAsync()`. `SendAsync(svc, class, inst, attr, data)` runs over `SendUnitData`. |
| `EipUdpTransport` | UDP I/O transport (port 2222) — send + receive callbacks |
| `ForwardOpenConfig` | Originator-side I/O connection parameters |
| `ScannerConnection` | Active I/O connection from the scanner side |

### `EthernetIPSharp.Connections`

| Type | What it is |
|---|---|
| `ConnectionManagerObject` | Implements the Connection Manager CIP class (handles Forward Open/Close) |
| `ForwardOpenRequest` | Binary parser for Forward Open / Large Forward Open |
| `IoConnection` | Per-connection state (CIDs, RPIs, safety state, timers) |
| `ConnectionPathParser` | Extracts assembly instances from a Forward Open path |
| `ISafetyConnectionHandler` | Interface ConnectionManager calls into for safety validation |

### `EthernetIPSharp.Device`

| Type | What it is |
|---|---|
| `VirtualDevice` | Abstract base. Wires together adapter, UDP transport, dispatcher, and assemblies |
| `StandardDevice` | Sealed non-safety device |
| `AssemblyObject` | CIP Assembly (0x04) with byte buffer + `DataChanged` event |
| `IdentityObject`, `TcpIpInterfaceObject`, `EthernetLinkObject` | Standard CIP objects pre-registered |

### `EthernetIPSharp.Safety`

| Type | What it is |
|---|---|
| `SafetyDevice` | Target-side safety adapter (extends `VirtualDevice`) |
| `SafetyScannerConnection` | Originator-side safety connection pair (server + client) |
| `SafetyFrameCodec` | Safety frame encode/decode (Base + Extended, Short + Long) |
| `SafetyCrc` | All five CRCs (S1, S2, S3, S4, S5) with lookup tables |
| `SafetyCpcrc` | Connection Parameter CRC computation |
| `SafetyNetworkSegment` | Forward Open safety segment (0x50) parse/encode |
| `SafetySupervisorObject` | Safety Supervisor CIP class (0x39) |
| `SafetyValidatorObject` | Safety Validator CIP class (0x3A) |
| `ModeByte`, `SafetyNetworkNumber`, `UniqueNetworkId`, `SafetyConfigurationId` | Strongly-typed safety identifiers |
| `SafetyForwardOpenBuilder`, `SafetyForwardOpenConfig` | Originator-side Forward Open builder |

### `EthernetIPSharp.Logix`

| Type | What it is |
|---|---|
| `LogixDispatcher` | Server side. Dispatches tag services + UDT template queries |
| `TagClient` | Client side. Connect to a real PLC and read/write tags |
| `TagDatabase`, `Tag` | In-memory tag store with `ValueChanged` events |
| `LogixDataTypes` | Standard Logix atomic types |
| `StructureValue` | Helper for reading/writing UDT structures by member name |
| `TemplateObject`, `SymbolObject` | Template Read and `Get_Instance_Attribute_List` support |
| `MultiServiceHandler` | Multiple Service Packet batching |

---

## CIP services supported

| Service | Code | Description |
|---|---|---|
| Get Attribute All | 0x01 | Read all attributes |
| Set Attribute All | 0x02 | Write all attributes |
| Get Attribute List | 0x03 | Read selected attributes |
| Reset | 0x05 | Reset CIP object |
| Multiple Service Packet | 0x0A | Batch multiple requests in one frame |
| Get Attribute Single | 0x0E | Read one CIP attribute |
| Set Attribute Single | 0x10 | Write one CIP attribute |
| Read Tag | 0x4C | Read tag data (symbolic or instance ID) |
| Write Tag | 0x4D | Write tag data with type validation |
| Forward Close | 0x4E | Close I/O connection |
| Read Modify Write | 0x4E | Bit-level OR/AND mask modification |
| Read Tag Fragmented | 0x52 | Chunked read for large tags |
| Write Tag Fragmented | 0x53 | Chunked write for large tags |
| Forward Open | 0x54 | Establish I/O connection |
| Get Instance Attribute List | 0x55 | Browse tags / instances (paginated) |
| Large Forward Open | 0x5B | Forward Open with 32-bit connection size fields |

---

## CIP Safety details

CIP Safety is a SIL-3-capable layer on top of standard EtherNet/IP. This library implements both producer (target) and consumer (originator) roles. Wire-format details (frame layouts, CRC polynomials, timing constants) follow the published CIP Safety specification — refer to the spec for protocol-level documentation.

**A "safety connection" is a pair of two underlying connections** — server and client — one in each direction for full bidirectional safety. Each carries the producer's safety data plus its own time-coordination (TCOO) exchange.

**Connection establishment:**
- Originator computes the Connection Parameter CRC over the Forward Open fields and includes it in the safety segment
- Target validates CPCRC, TUNID, electronic key, and Safety Configuration Identifier before accepting
- Production starts immediately on Forward Open; outgoing frames stay in IDLE mode until the first TCOO arrives and time coordination is established

**Safety ownership (work in progress):**
The full safety ownership state machine (Propose_TUNID / Apply_TUNID / Configure / Run / Idle transitions in the Safety Supervisor) is not yet implemented. The current target-side check is that the originator's SNN and the safety configuration signature (SCCRC + SCTS) must match what the target was commissioned with — connections are accepted if both match. Commissioning workflows (changing a target's owner or its config from the originator side) are not yet supported.

---

## Running CIP Safety on Windows — host tuning

Producer-side timing for CIP Safety is sensitive to two things *outside* the .NET code:

**1. NIC configuration.** "Green" features on consumer Realtek NICs can renegotiate the link down to 10 Mbps half-duplex, which triggers CSMA/CD backoff and produces 100–180 ms wire gaps that will drop safety connections at 10 ms RPI. On a Realtek 2.5GbE NIC, disable:

| Setting | Set to |
|---|---|
| Green Ethernet | Disabled |
| Power Saving Mode | Disabled |
| Interrupt Moderation | Disabled |
| Selective Suspend | Disabled |
| Advanced EEE | Disabled |
| Gigabit Lite | Disabled |

Then verify `Get-NetAdapter -Name Ethernet` shows `LinkSpeed: 1 Gbps` and `FullDuplex: True`. After fixing these, observed wire-level max gap at 10 ms RPI is **~20–26 ms over multi-hour runs**, comparable to a hardware 1734-IB8S on the same network.

**2. Windows scheduler tail.** With `ThreadPriority.Highest`, CPU pinning, `GCLatencyMode.SustainedLowLatency`, and a high-resolution waitable timer, the producer thread's worst wakeup overshoot on stock Windows is **~10 ms** (median ~400 µs). This is the floor on stock Windows due to DPC processing, CPU C-state exit, and System Management Mode. For tighter tolerances, look into MMCSS Pro Audio (`AvSetMmThreadCharacteristics`) or BIOS C-state disable.

Set `ETHERNETIPSHARP_LAG_CSV=1` before launching the adapter to write per-iteration producer-thread timing (`iter_us, wake_overshoot_us, produce_us, total_us`) to `%TEMP%\lag_conn_*.csv` for post-run analysis.

## Known limitations

- 10 ms RPI runs stably for hours on Windows with the NIC tuning above. Tighter RPIs (≤ 5 ms) likely require MMCSS Pro Audio or BIOS C-state disable.
- No persistent storage — assembly contents and tag values are in-memory only.
- Originator-side connection bridging through multiple hops is not implemented.
- Safety reset / safety configuration apply services are wired in but not extensively interop-tested.

---

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.

```
Copyright 2026 Cristian Mori

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
