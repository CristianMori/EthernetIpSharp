"""End-to-end round-trip against pycomm3 — the de facto Python client for
Allen-Bradley Logix controllers.

The C# port's own unit tests already prove the server speaks to its own
TagClient.  This test proves it speaks the exact wire dialect pycomm3 (and
by extension Studio 5000) expects.  Covers every atomic CIP type the server
exposes, including the Logix bit-string family and SHORT_STRING.

The server-under-test is `samples/SampleLogixHost`, launched as a
subprocess on a free loopback port.  The test is skipped automatically if
pycomm3 is not installed or the .NET SDK / sample DLL cannot be found.

Mirrors `../../EthernetIPPython/tests/pycomm3/test_pycomm3_roundtrip.py`
one-for-one so the same assertion set runs against both ports.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pycomm3 = pytest.importorskip("pycomm3")

# (name, type_code, initial_value, write_value) — bit-string types take a
# list of booleans per pycomm3's write encoding; atomics take a Python
# int / float / bool / str.
BOOL         = "BOOL"
SINT         = "SINT"
INT          = "INT"
DINT         = "DINT"
LINT         = "LINT"
USINT        = "USINT"
UINT         = "UINT"
UDINT        = "UDINT"
ULINT        = "ULINT"
REAL         = "REAL"
LREAL        = "LREAL"
BYTE         = "BYTE"
WORD         = "WORD"
DWORD        = "DWORD"
LWORD        = "LWORD"
SHORT_STRING = "SHORT_STRING"


def _bits(value: int, width: int) -> list:
    return [bool((value >> i) & 1) for i in range(width)]


TYPES = [
    ("TestBool",  BOOL,  True,       False),
    ("TestSint",  SINT,  -5,         127),
    ("TestInt",   INT,   -1234,      32000),
    ("TestDint",  DINT,  -1_000_000, 2_000_000_000),
    ("TestLint",  LINT,  -1,         0x7FFF_FFFF_FFFF_FFFF),
    ("TestUsint", USINT, 42,         0xFF),
    ("TestUint",  UINT,  0xBEEF,     0xFFFF),
    ("TestUdint", UDINT, 0xDEADBEEF, 0xFFFF_FFFF),
    ("TestUlint", ULINT, 1_234_567_890_123, 0xFFFF_FFFF_FFFF_FFFF),
    ("TestReal",  REAL,  3.14,       -2.71828),
    ("TestLreal", LREAL, 3.141592653589793, -2.718281828459045),
    ("TestByte",  BYTE,  _bits(0xAB, 8),              _bits(0xCD, 8)),
    ("TestWord",  WORD,  _bits(0x1234, 16),           _bits(0xABCD, 16)),
    ("TestDword", DWORD, _bits(0xDEADBEEF, 32),       _bits(0xCAFEBABE, 32)),
    ("TestLword", LWORD, _bits(0x1234_5678_9ABC_DEF0, 64),
                          _bits(0xFEDC_BA98_7654_3210, 64)),
]


REPO_ROOT   = Path(__file__).resolve().parents[2]
SAMPLE_PROJ = REPO_ROOT / "samples" / "SampleLogixHost" / "SampleLogixHost.csproj"
SAMPLE_DLL  = REPO_ROOT / "samples" / "SampleLogixHost" / "bin" / "Release" / "net8.0" / "SampleLogixHost.dll"


def _grab_free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_tcp(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as e:
            last_err = e
            time.sleep(0.1)
    raise RuntimeError(f"server at {host}:{port} did not come up within {timeout}s "
                       f"(last error: {last_err!r})")


def _ensure_sample_built() -> None:
    """Build the sample host once per test session if its DLL is missing."""
    if SAMPLE_DLL.exists():
        return
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        pytest.skip("`dotnet` SDK not on PATH — cannot build SampleLogixHost")
    proc = subprocess.run(
        [dotnet, "build", str(SAMPLE_PROJ), "-c", "Release", "-nologo", "--verbosity", "quiet"],
        cwd=str(REPO_ROOT), capture_output=True, text=True,
    )
    if proc.returncode != 0 or not SAMPLE_DLL.exists():
        pytest.fail("Failed to build SampleLogixHost:\n"
                    f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")


@pytest.fixture(scope="module")
def sample_host():
    _ensure_sample_built()
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        pytest.skip("`dotnet` SDK not on PATH")

    port = _grab_free_port()
    cmd = [dotnet, str(SAMPLE_DLL), "--port", str(port), "--bind", "127.0.0.1"]

    # On Windows, create a new process group so we can send CTRL_BREAK; on
    # Unix just let SIGTERM/SIGKILL do the work.
    popen_kwargs: dict = dict(cwd=str(REPO_ROOT), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]

    proc = subprocess.Popen(cmd, **popen_kwargs)
    try:
        _wait_tcp("127.0.0.1", port, timeout=15.0)
        yield port
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)


def _values_match(ty: str, got, expected) -> bool:
    if ty == BOOL:
        return bool(got) == bool(expected)
    if ty == REAL:
        return abs(float(got) - float(expected)) < 1e-5
    if ty == LREAL:
        return abs(float(got) - float(expected)) < 1e-12
    if ty == DWORD:
        # pycomm3 collapses a raw DWORD read to bit 0 — the full-32 proof
        # read below covers the whole word.
        exp_bit = expected[0] if isinstance(expected, (list, tuple)) else bool(expected & 1)
        return bool(got) == exp_bit
    if ty in (BYTE, WORD, LWORD):
        got_list = list(got) if isinstance(got, (list, tuple)) else [got]
        exp_list = list(expected) if isinstance(expected, (list, tuple)) else [expected]
        return got_list == exp_list
    return got == expected


def test_pycomm3_every_atomic_type_round_trips(sample_host):
    port = sample_host
    from pycomm3 import LogixDriver

    with LogixDriver(f"127.0.0.1:{port}", init_tags=True, init_program_tags=False) as plc:
        tag_names = sorted(plc.tags.keys())
        expected_names = {t[0] for t in TYPES} | {"TestShortString"}
        missing = expected_names - set(tag_names)
        assert not missing, (
            f"pycomm3 did not enumerate expected tags.\n"
            f"  missing : {sorted(missing)}\n"
            f"  returned: {tag_names}"
        )

        failures: dict[str, object] = {}

        for name, ty, initial, write_val in TYPES:
            r = plc.read(name)
            if r.error:
                failures[name] = ("read-init-error", r.error)
                continue
            initial_ok = _values_match(ty, r.value, initial)

            w = plc.write((name, write_val))
            if w.error:
                failures[name] = ("write-error", w.error,
                                   {"initial": r.value, "wrote": write_val})
                continue

            r2 = plc.read(name)
            if r2.error:
                failures[name] = ("read-back-error", r2.error)
                continue
            readback_ok = _values_match(ty, r2.value, write_val)
            if not (initial_ok and readback_ok):
                failures[name] = ("mismatch", {
                    "initial":     r.value,
                    "wrote":       write_val,
                    "back":        r2.value,
                    "initial_ok":  initial_ok,
                    "readback_ok": readback_ok,
                })

        # DWORD full-32 proof read — reads the whole word as a BOOL array,
        # verifying the server stored every bit (not just bit 0).
        r = plc.read("TestDword{32}")
        if r.error or list(r.value) != _bits(0xCAFEBABE, 32):
            failures["TestDword{32}"] = ("mismatch", {
                "error": r.error,
                "val":   list(r.value) if r.value is not None else None,
                "want":  _bits(0xCAFEBABE, 32),
            })

        # SHORT_STRING round-trip — write "hello", read it back.
        r = plc.read("TestShortString")
        if r.error:
            failures["TestShortString"] = ("read-init-error", r.error)
        else:
            w = plc.write(("TestShortString", "hello"))
            if w.error:
                failures["TestShortString"] = ("write-error", w.error)
            else:
                r2 = plc.read("TestShortString")
                if r2.error or r2.value != "hello":
                    failures["TestShortString"] = ("mismatch",
                                                     {"back": r2.value, "err": r2.error})

    assert not failures, "pycomm3 round-trip failures:\n" + "\n".join(
        f"  {k}: {v!r}" for k, v in failures.items()
    )
