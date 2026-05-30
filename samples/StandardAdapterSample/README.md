# StandardAdapterSample

Plain (non-safety) EtherNet/IP I/O adapter. Defaults match the Studio 5000 *Generic Ethernet Module* configuration so you can drop it into an existing PLC project with no additional setup.

## Run

```sh
# Default — binds 0.0.0.0:44818, assemblies 100/102/105
dotnet run --project samples/StandardAdapterSample

# Bind to a specific NIC IP
dotnet run --project samples/StandardAdapterSample -- --bind=192.168.1.84

# Different assemblies / sizes
dotnet run --project samples/StandardAdapterSample -- \
    --asm-input=120 --input-bytes=200 --asm-output=121 --output-bytes=200
```

## CLI options

| Flag | Meaning | Default |
|---|---|---|
| `--bind=<ip>` | Local IP to bind on | `0.0.0.0` (all NICs) |
| `--vendor=<n>` | Vendor ID | `1` (Rockwell) |
| `--device-type=<n>` | Device type code | `0x0C` (Communications Adapter) |
| `--product-code=<n>` | Product code | `1` |
| `--serial=<hex>` | 32-bit device serial number | `0xC0FFEE42` |
| `--product=<text>` | Product Name string | `EthernetIPSharp Standard Adapter` |
| `--asm-input=<n>` | Input (T→O) assembly instance | `100` |
| `--asm-output=<n>` | Output (O→T) assembly instance | `102` |
| `--asm-config=<n>` | Configuration assembly instance | `105` |
| `--input-bytes=<n>` | Input assembly size in bytes | `500` (125 DINTs) |
| `--output-bytes=<n>` | Output assembly size in bytes | `496` (124 DINTs) |
| `--config-bytes=<n>` | Config assembly size in bytes | `10` |

## What you need on the other end

Any EtherNet/IP scanner. To configure in Studio 5000:

| Studio 5000 field | Value |
|---|---|
| Module type | Generic Ethernet Module |
| Comm Format | Data — DINT |
| Address | `192.168.1.84` (or whatever you bound to) |
| Input Assembly Instance | `100`  Size: `125` |
| Output Assembly Instance | `102`  Size: `124` |
| Configuration Assembly Instance | `105`  Size: `10` |
| RPI | 10–1000 ms (any) |

## Notes

- A 4-byte Run/Idle header is added by the scanner on the O→T direction (496 + 4 = 500 wire bytes); T→O has no such header. That's why input is 125 DINTs and output is 124 DINTs.
- The sample pre-fills the input assembly with an incrementing ramp (`1..125`) so you can immediately see produced data on the scanner side.
- For a self-contained end-to-end test without a PLC, pair this with `SampleStandardScanner` — defaults on both sides match.
