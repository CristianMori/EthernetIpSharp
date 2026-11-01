# Building with bflat (native AOT, no .NET runtime)

[bflat](https://github.com/bflattened/bflat) compiles C# directly to a native binary
with no managed runtime dependency. For a tool that wraps a Logix tag reader into a
single-file CLI, bflat produces a ~2 MB native `.exe` where `dotnet publish
--self-contained -p:PublishAot=true` would ship ~50 MB. No external packages are
needed — `EthernetIPSharp` has zero `PackageReference`s, so the entire closure is BCL
only, and the whole stack is AOT-clean (no `Activator.CreateInstance`, no
`Assembly.Load`, no late-bound reflection).

The library is **built and shipped with the standard .NET SDK** (`dotnet build`,
`dotnet pack`). bflat support here is additive, not a replacement.

## Quick start

1. Download bflat for your platform from the
   [releases page](https://github.com/bflattened/bflat/releases) and put `bflat`
   (or `bflat.exe`) on your `PATH`.
2. From the repo root:

   ```powershell
   # Windows (PowerShell)
   .\tools\bflat\build-sampletag.ps1
   ```

   ```bash
   # Linux / macOS / Git Bash
   ./tools/bflat/build-sampletag.sh
   ```

   The scripts pass every `.cs` under `samples/SampleTag`,
   `src/EthernetIPSharp.Logix`, `src/EthernetIPSharp.Cip`,
   `src/EthernetIPSharp.Connections`, and `src/EthernetIPSharp.Protocol` to bflat,
   plus the synthetic `_implicit_usings.cs` in this folder.

3. Run the output:

   ```powershell
   .\sample-tag.exe --plc=192.168.1.96 --tag=Amix --no-write
   ```

## What's in this folder

| File | Purpose |
|---|---|
| `_implicit_usings.cs` | Reinstates the net8.0 `ImplicitUsings` set (`System`, `System.Collections.Generic`, `System.IO`, `System.Linq`, `System.Net.Http`, `System.Threading`, `System.Threading.Tasks`). bflat does not read csproj files, so the SDK's auto-added `global using` directives never materialize. |
| `build-sampletag.ps1` | PowerShell driver. Options: `-BflatPath`, `-OutPath`, `-Arch`, `-OptSize`. |
| `build-sampletag.sh`  | POSIX driver. Env vars: `BFLAT`, `OUT`, `ARCH`, `OPT`. |

## Building a different target

The scripts hard-code the project closure for `SampleTag`. For another sample, pass
the dependency closure of that sample's `.csproj`. The closures are:

| Sample                 | Project closure                                                                                  |
|------------------------|--------------------------------------------------------------------------------------------------|
| `SampleTag`            | Logix + Cip + Connections + Protocol                                                             |
| `CipEchoServer`        | Cip + Protocol + Connections + Device                                                            |
| `SampleStandardScanner`| Cip + Protocol + Connections                                                                     |
| `StandardAdapterSample`| Cip + Protocol + Connections + Device                                                            |
| `SampleSafetyScanner`  | Cip + Protocol + Connections + Device + Safety                                                   |
| `SafetyAdapterSample`  | Cip + Protocol + Connections + Device + Safety                                                   |

Copy `build-sampletag.ps1` / `.sh`, change the project list, and point `-OutPath`
/ `$OUT` at a different file name.

## Notes

- Verified with **bflat 8.0.2** against the current `master`.
- The repo targets `net8.0`; bflat ships a matching 8.x branch. Use a bflat release
  that matches the `TargetFramework` of the csproj files (currently `net8.0`).
- Optimization defaults to `-Ot` (favor speed). Pass `-OptSize` / `OPT=-Os` for
  smaller binaries at some runtime cost.
- To cross-compile to Linux from Windows (or vice versa), see bflat's `--os` and
  `--libc` flags. The scripts here build for the host OS.
