# SafetyAdapterSample

CIP Safety EtherNet/IP adapter (target side). Accepts a safety connection pair from a Logix originator and exchanges CRC-protected, time-coordinated safety I/O at the configured RPI.

## Run

```sh
# Built-in profile that matches a real Allen-Bradley ControlLogix
dotnet run --project samples/SafetyAdapterSample -- --profile=plc

# Different profile (used by some safety emulators)
dotnet run --project samples/SafetyAdapterSample

# Fully custom
dotnet run --project samples/SafetyAdapterSample -- \
    --bind=10.0.0.5 --vendor=12 --snn=4D90_0101_A35C --node=0x0A000005
```

## CLI options

| Flag | Meaning | Default |
|---|---|---|
| `--profile=<test2\|plc>` | Preconfigured target identity / SNN | `test2` |
| `--bind=<ip>` | Local IP to bind on (must be on a NIC) | from profile |
| `--vendor=<n>` | Vendor ID (1=Rockwell, 12=common emulator vendor) | from profile |
| `--serial=<hex>` | 32-bit device serial number | from profile |
| `--product=<text>` | Product Name string returned by Identity object | from profile |
| `--snn=<hex_6bytes>` | Safety Network Number (12 hex chars, e.g. `4D90_0101_A35C`) | from profile |
| `--node=<hex>` | Safety node address (your IP packed BE as uint32) | from profile |
| `--asm-data1=<n>` | First safety data assembly instance | from profile |
| `--asm-data2=<n>` | Second safety data assembly instance | from profile |
| `--asm-config=<n>` | Configuration assembly instance | from profile |
| `--halt-threshold=<sec>` | Halt on first connection drop after running this many seconds (test mode). Default 60 — set to 5 to halt fast |
| `--startup-trace=<sec>` | Emit per-frame `[SU-*]` logs for the first N seconds of each connection. Off by default (slows the hot path). |

## What you need on the other end

A safety scanner — real ControlLogix with a safety I/O module configured as `ETHERNET-MODULE` pointing at this adapter's IP, or a compatible Logix emulator. The PLC project must have the matching SNN, electronic key, and SCID (Safety Configuration Identifier).

## Notes

- Identity: this sample serves a *fake* identity meant to look like a 1734 safety I/O module. Adjust the profile or use CLI options to mimic whatever device the originator expects.
- Production starts immediately on Forward Open; outgoing frames are IDLE until the first TCOO arrives from the originator and time coordination is established.
- Set `ETHERNETIPSHARP_LAG_CSV=1` before launching to write per-iteration producer-thread timing to `%TEMP%\lag_conn_*.csv`. Useful for diagnosing scheduling jitter.
- See the **Running CIP Safety on Windows — host tuning** section in the project README for NIC configuration that materially affects stability at 10ms RPI.
