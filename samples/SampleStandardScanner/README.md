# SampleStandardScanner

Class 1 I/O scanner (originator) for non-safety EtherNet/IP. Opens a cyclic O→T / T→O connection to a target adapter and streams data both ways at the configured RPI.

## Run

```sh
# Self-contained end-to-end test against StandardAdapterSample on this host:
#   Terminal 1:  dotnet run --project samples/StandardAdapterSample
#   Terminal 2:  dotnet run --project samples/SampleStandardScanner -- --target=127.0.0.1

# Against a real adapter
dotnet run --project samples/SampleStandardScanner -- --target=192.168.1.84

# Slower RPI
dotnet run --project samples/SampleStandardScanner -- --target=10.0.0.5 --rpi=20000
```

## CLI options

| Flag | Meaning | Default |
|---|---|---|
| `--target=<ip>` | Target adapter IP | `127.0.0.1` |
| `--rpi=<us>` | Requested packet interval, microseconds | `10000` (10 ms) |
| `--asm-output=<n>` | O→T assembly (we send) | `102` |
| `--asm-input=<n>` | T→O assembly (we receive) | `100` |
| `--asm-config=<n>` | Config assembly | `105` |
| `--output-bytes=<n>` | O→T size in bytes | `496` |
| `--input-bytes=<n>` | T→O size in bytes | `500` |
| `--orig-vendor=<n>` | Originator vendor ID | `0x1234` |
| `--orig-serial=<hex>` | Originator serial number | `0xC0FFEE99` |
| `--duration=<sec>` | Stop after N seconds (0 = forever) | `0` |

## What you need on the other end

Any non-safety EtherNet/IP target adapter that exposes Class 1 I/O assemblies of the matching sizes. Easiest counterpart is `StandardAdapterSample` (defaults pair cleanly).

## Notes

- The scanner pre-fills its O→T buffer with an incrementing ramp at index 0 so you can see your data appear on the target's "Output" side.
- It also reads the T→O data each cycle and prints the first DINT — handy for watching the target's produced ramp.
- The 4-byte Run/Idle header on the O→T direction is added by the scanner automatically; the `--output-bytes` value is the *data* size (496), wire size becomes 500.
