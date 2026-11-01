#!/usr/bin/env bash
# Build samples/SampleTag as a single native binary with bflat.
#
# Usage:
#   ./tools/bflat/build-sampletag.sh                       # bflat on PATH, writes ./sample-tag
#   BFLAT=/path/to/bflat ./tools/bflat/build-sampletag.sh  # explicit bflat
#   OUT=/tmp/sample-tag ./tools/bflat/build-sampletag.sh   # explicit output
#
# bflat releases: https://github.com/bflattened/bflat/releases
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

BFLAT="${BFLAT:-bflat}"
OUT="${OUT:-sample-tag}"
ARCH="${ARCH:-x64}"
OPT="${OPT:--Ot}"

mapfile -t sources < <(
  find \
    "$root/samples/SampleTag" \
    "$root/src/EthernetIPSharp.Logix" \
    "$root/src/EthernetIPSharp.Cip" \
    "$root/src/EthernetIPSharp.Connections" \
    "$root/src/EthernetIPSharp.Protocol" \
    -name '*.cs' -not -path '*/bin/*' -not -path '*/obj/*'
)

echo "Compiling $((${#sources[@]} + 1)) files -> $OUT"

"$BFLAT" build \
    -o "$OUT" \
    --target Exe \
    --arch "$ARCH" \
    "$OPT" \
    "$here/_implicit_usings.cs" \
    "${sources[@]}"

ls -la "$OUT"
