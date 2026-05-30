# SampleSafetyScanner

CIP Safety originator (scanner). Opens a safety connection pair against a real safety I/O target, runs the time-coordination handshake, and streams safety frames both directions.

## Run

```sh
# Default target: 1734-IB8S in slot 1 behind a 1734-ENT EtherNet/IP adapter at 192.168.1.76
dotnet run --project samples/SampleSafetyScanner

# Different IP / slot
dotnet run --project samples/SampleSafetyScanner -- --target=192.168.1.76 --slot=1
```

## CLI options

| Flag | Meaning | Default |
|---|---|---|
| `--target=<ip>` | Target EtherNet/IP adapter IP | `192.168.1.76` |
| `--slot=<n>` | Backplane slot of the safety module | `1` |
| `--orig-vendor=<n>` | Originator vendor ID | `1` (Rockwell) |
| `--orig-serial=<hex>` | Originator serial number | `0x012FE10E` |

## What you need on the other end

A real 1734-IB8S safety input module installed in the backplane of a 1734-ENT EtherNet/IP adapter at the configured `--target` IP and `--slot`. The sample's hardcoded identity fields (target SNN, SCCRC, SCTS, electronic key, configuration data) are specific to a known-working 1734-IB8S commissioned by Logix.

## Important: device-specific identity values

The sample contains hardcoded:
- **TUNID** (Target Unique Network Identifier — the SNN burned into the safety module)
- **SCCRC + SCTS** (Safety Configuration Identifier — proves the originator has the right config)
- **Electronic key** (vendor, device type, product code, major/minor revision)
- **Server and client connection serial numbers, RPIs, ping interval multipliers**

These values come from a working PLC project that owns the module. To use the sample against a *different* 1734-IB8S, you'll either need to:
- Capture them from a working PLC's Forward Open over Wireshark, or
- Read them from your Logix project file, or
- Commission the module to your originator (commissioning workflow is not implemented in this library — see *Safety ownership* in the project README).

## Notes

- The originator's SNN must match what the target was last commissioned with, OR the target needs to be commissioned to a new owner first.
- A safety connection is really a *pair* of standard connections (server + client) — Forward Open is sent twice with different parameters.
- See the project README's **Running CIP Safety on Windows — host tuning** section for NIC settings that materially affect stability at tight RPIs.
