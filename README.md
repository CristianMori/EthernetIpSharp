# EthernetIPSharp — EtherNet/IP Libary in C#

A full CIP protocol stack in C# (.NET 8) that can simulate EtherNet/IP adapter devices and Logix PLC tag servers. Tested with real Allen-Bradley ControlLogix PLCs.

## What it does

- **Adapter mode**: Simulates a Generic Ethernet Module. A real PLC connects to it, establishes I/O connections via Forward Open, and exchanges cyclic data at configurable RPI.
- **Logix tag server**: Responds to Read Tag, Write Tag, tag browsing, template queries, and Multiple Service Packet — just like a real ControlLogix.
- **Scanner mode**: Connects to real devices (or other simulators), sends explicit CIP messages, and establishes I/O connections.

## Architecture

```
EthernetIPSharp.Cip           Pure CIP protocol — no I/O dependencies
  ICipDispatch        Central dispatch interface
  CipDispatcher       Routes requests through CIP object tree
  CipPath             EPATH parser (logical + symbolic segments)
  MrCodec             Message Router request/response codec
  EncapsulationHeader 24-byte TCP framing codec
  CpfParser           Common Packet Format codec

EthernetIPSharp.Protocol       Transport layer — TCP and UDP sockets
  EipAdapter          TCP 44818 listener (server/target side)
  EipScanner          TCP 44818 client (originator/scanner side)
  EipUdpTransport     UDP 2222 I/O data send/receive

EthernetIPSharp.Connections    Connection lifecycle
  ConnectionManager   Forward Open/Close, connection tracking
  ForwardOpenRequest  Binary parser for Forward Open parameters
  ConnectionPath      Assembly path extraction

EthernetIPSharp.Device         Virtual device composition
  VirtualDevice       Ties everything together — dispatcher, assemblies, I/O timers
  AssemblyObject      CIP Assembly (0x04) with byte buffer I/O

EthernetIPSharp.Logix          Logix PLC simulator
  LogixDispatcher     CipDispatcher subclass with symbolic tag dispatch
  Tag                 Tag data object with ValueChanged events
  TagDatabase         In-memory tag store with change notifications
  TagServices         Read/Write Tag, Fragmented, Read Modify Write
  SymbolObject        Tag browsing via Get_Instance_Attribute_List
  TemplateObject      UDT structure definitions and Template Read

EthernetIPSharp.Host           Console test program
```

## Quick start

### Simulate a Generic Ethernet Module

```csharp
var identity = new IdentityInfo
{
    VendorId = 0x0001,
    DeviceType = 0x000C,
    ProductCode = 1,
    MajorRevision = 1,
    MinorRevision = 0,
    SerialNumber = 0xC0FFEE42,
    ProductName = "My Simulator",
};

await using var device = new VirtualDevice(identity, IPAddress.Parse("192.168.1.100"));

// Configure assemblies matching your Studio 5000 Generic Ethernet Module
device.AddAssembly(100, 500, "T->O Input");   // 125 DINTs
device.AddAssembly(101, 496, "O->T Output");  // 124 DINTs
device.AddAssembly(10, 0, "Configuration");

await device.StartAsync();

// Write data the PLC will read as Input
device.Assemblies.GetAssembly(100)!.Write(0, 42);

// Read data the PLC writes as Output
int plcOutput = device.Assemblies.GetAssembly(101)!.Read<int>(0);
```

### Simulate a Logix PLC (tag server)

```csharp
var logix = new LogixDispatcher();

// Add tags
logix.Tags.AddTag("rate", LogixDataTypes.DINT).Write(0, 1500);
logix.Tags.AddTag("temperature", LogixDataTypes.REAL).Write(0, 72.5f);
logix.Tags.AddTag("counts", LogixDataTypes.INT, elementCount: 100);

// Get notified when a client writes a tag
logix.Tags.FindByName("rate")!.ValueChanged += (tag, change) =>
{
    Console.WriteLine($"rate changed to {tag.Read<int>()}");
};

// Start adapter
var adapter = new EipAdapter(logix, identityInfo);
await adapter.ListenAsync(IPAddress.Any, 44818);

// Any EtherNet/IP client can now:
//   - Read/Write tags by name
//   - Browse tags
//   - Query structure templates
```

### Use the scanner to connect to a device

```csharp
await using var scanner = new EipScanner();
await scanner.ConnectAsync("192.168.1.100");

// Read Identity vendor ID
var response = await scanner.SendExplicitAsync(0x0E,
    new byte[] { 0x20, 0x01, 0x24, 0x01, 0x30, 0x01 }, []);

// Establish I/O connection
var conn = await scanner.ForwardOpenAsync(new ForwardOpenConfig
{
    ConsumedAssembly = 101,
    ProducedAssembly = 100,
    ConfigAssembly = 10,
    ConsumedSize = 32,
    ProducedSize = 32,
    Rpi = 10_000, // 10ms
});

// Exchange data
conn.Write(0, 42);                    // Send to device
int received = conn.Read<int>(0);     // Read from device

await conn.CloseAsync();
```

## Compatibility

- Works with real Allen-Bradley ControlLogix and CompactLogix PLCs
- Tested with pycomm3 (Python) — tag read/write via Unconnected Send
- Compatible with standard EtherNet/IP clients
- Supports Class 1 transport with run/idle header handling

## CIP services supported

| Service | Code | Description |
|---|---|---|
| Read Tag | 0x4C | Read tag data by symbolic name or instance ID |
| Write Tag | 0x4D | Write tag data with type validation |
| Read Tag Fragmented | 0x52 | Chunked read for large tags |
| Write Tag Fragmented | 0x53 | Chunked write for large tags |
| Read Modify Write | 0x4E | Bit-level modification with OR/AND masks |
| Multiple Service Packet | 0x0A | Batch multiple requests in one frame |
| Get Instance Attribute List | 0x55 | Browse tags (paginated) |
| Get Attribute Single | 0x0E | Read one CIP attribute |
| Set Attribute Single | 0x10 | Write one CIP attribute |
| Get Attribute All | 0x01 | Read all attributes |
| Forward Open | 0x54 | Establish I/O connection |
| Large Forward Open | 0x5B | Forward Open with 32-bit size fields |
| Forward Close | 0x4E | Close I/O connection |

## Building and testing

```bash
dotnet build
dotnet test     # 79 tests
```

## Project structure

```
src/
  EthernetIPSharp.Cip/          Core CIP protocol (no I/O dependencies)
  EthernetIPSharp.Protocol/     TCP/UDP transport (adapter + scanner)
  EthernetIPSharp.Connections/  Forward Open/Close, connection lifecycle
  EthernetIPSharp.Device/       Virtual device composition
  EthernetIPSharp.Logix/        Logix PLC tag simulator
  EthernetIPSharp.Host/         Console test program

tests/
  EthernetIPSharp.Protocol.Tests/   Encapsulation, Forward Open, scanner loopback tests
  EthernetIPSharp.Logix.Tests/      Tag read/write, addressing, edge cases, mock tests
```

## License

MIT

Copyright (c) 2026 Cristian Mori

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
