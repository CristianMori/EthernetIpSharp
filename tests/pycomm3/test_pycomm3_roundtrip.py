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

        # --- Yellow rows -----------------------------------------------------
        def check(label: str, cond: bool, detail=None):
            if not cond:
                failures[label] = ("mismatch", detail)

        # Row 17: 1-D array of atomics — indexed read/write
        r = plc.read("DintArr[5]")
        check("17 DintArr[5] read",
              not r.error and r.value == 105,
              {"err": r.error, "val": r.value})
        w = plc.write(("DintArr[5]", 999))
        r2 = plc.read("DintArr[5]")
        check("17 DintArr[5] round-trip",
              not w.error and r2.value == 999,
              {"w": w.error, "back": r2.value})

        # Row 18: whole-array read
        r = plc.read("DintArr{10}")
        check("18 DintArr{10}",
              not r.error and list(r.value)[0] == 100 and list(r.value)[9] == 109,
              {"err": r.error, "vals": list(r.value) if r.value else None})

        # Rows 19-20: fragmented read + write of all 10 elements
        w = plc.write(("DintArr{10}", list(range(1000, 1010))))
        r = plc.read("DintArr{10}")
        check("19-20 fragmented r/w",
              not w.error and list(r.value) == list(range(1000, 1010)),
              {"w": w.error, "back": list(r.value) if r.value else None})

        # Row 21: bit of atomic — FlagsDint.N
        r = plc.read("FlagsDint.1")
        check("21 FlagsDint.1 read",
              not r.error and bool(r.value) is True,
              {"err": r.error, "val": r.value})
        w = plc.write(("FlagsDint.0", True))
        r2 = plc.read("FlagsDint.0")
        check("21 FlagsDint bit write",
              not w.error and bool(r2.value) is True,
              {"w": w.error, "back": r2.value})

        # Row 22: BOOL array (DWORD-packed) — indexed bit read + write
        r = plc.read("Flags32[3]")
        check("22 Flags32[3] read",
              not r.error,
              {"err": r.error, "val": r.value})
        w = plc.write(("Flags32[7]", True))
        r2 = plc.read("Flags32[7]")
        check("22 Flags32 bit write",
              not w.error and bool(r2.value) is True,
              {"w": w.error, "back": r2.value})

        # Row 23: multi-dim array — Matrix[1,2]
        r = plc.read("Matrix[1,2]")
        check("23 Matrix[1,2] read",
              not r.error and r.value == 12,
              {"err": r.error, "val": r.value})
        w = plc.write(("Matrix[0,1]", 777))
        r2 = plc.read("Matrix[0,1]")
        check("23 Matrix write",
              not w.error and r2.value == 777,
              {"w": w.error, "back": r2.value})

        # Row 24: Logix STRING UDT whole-struct round-trip
        r = plc.read("Greeting")
        check("24 Greeting read",
              not r.error and r.value == "Hello pycomm3",
              {"err": r.error, "val": r.value})
        w = plc.write(("Greeting", "written back"))
        r2 = plc.read("Greeting")
        check("24 Greeting round-trip",
              not w.error and r2.value == "written back",
              {"w": w.error, "back": r2.value})

        # Row 25: STRING array
        w = plc.write(("GreetingArr[1]", "second"))
        r = plc.read("GreetingArr[1]")
        check("25 GreetingArr[1]",
              not w.error and not r.error and r.value == "second",
              {"w": w.error, "r": r.error, "val": r.value})

        # Row 26: UDT whole-struct read (returns dict)
        r = plc.read("MotorA")
        check("26 MotorA whole-struct",
              not r.error
              and isinstance(r.value, dict)
              and abs(r.value["Speed"] - 3.14) < 1e-4
              and r.value["Fault"] is True
              and r.value["RunCount"] == 42,
              {"err": r.error, "val": r.value})

        # Row 27: UDT member access
        r = plc.read("MotorA.Speed")
        check("27 MotorA.Speed",
              not r.error and abs(r.value - 3.14) < 1e-5,
              {"err": r.error, "val": r.value})
        r = plc.read("MotorA.RunCount")
        check("27 MotorA.RunCount",
              not r.error and r.value == 42,
              {"err": r.error, "val": r.value})
        w = plc.write(("MotorA.Speed", -1.5))
        r2 = plc.read("MotorA.Speed")
        check("27 MotorA.Speed write",
              not w.error and abs(r2.value - (-1.5)) < 1e-5,
              {"w": w.error, "back": r2.value})

        # Row 29: BOOL member of UDT
        r = plc.read("MotorA.Fault")
        check("29 MotorA.Fault read",
              not r.error and bool(r.value) is True,
              {"err": r.error, "val": r.value})
        w = plc.write(("MotorA.Fault", False))
        r2 = plc.read("MotorA.Fault")
        check("29 MotorA.Fault write",
              not w.error and bool(r2.value) is False,
              {"w": w.error, "back": r2.value})

        # Row 31: array of UDTs with member access
        w = plc.write(("MotorArr[1].Speed", 7.77))
        r = plc.read("MotorArr[1].Speed")
        check("31 MotorArr[1].Speed",
              not w.error and not r.error and abs(r.value - 7.77) < 1e-4,
              {"w": w.error, "r": r.error, "val": r.value})

        # TIMER UDT — same access pattern as a user UDT; this is just an
        # explicit witness that `MyTimer.PRE` and `MyTimer.EN` work.
        r = plc.read("MyTimer.PRE")
        check("TIMER MyTimer.PRE read", not r.error and r.value == 1000, {"err": r.error, "val": r.value})
        r = plc.read("MyTimer.EN")
        check("TIMER MyTimer.EN read", not r.error and bool(r.value) is True, {"err": r.error, "val": r.value})
        w = plc.write(("MyTimer.PRE", 2000)); r = plc.read("MyTimer.PRE")
        check("TIMER MyTimer.PRE write", not w.error and r.value == 2000, {"w": w.error, "back": r.value})
        w = plc.write(("MyTimer.EN", False)); r = plc.read("MyTimer.EN")
        check("TIMER MyTimer.EN write", not w.error and bool(r.value) is False, {"w": w.error, "back": r.value})

        # AOI-backing UDT — same mechanism, confirming AOI tags are not
        # special on the wire.
        r = plc.read("MyAOI.Enable")
        check("AOI MyAOI.Enable read", not r.error and bool(r.value) is True, {"err": r.error, "val": r.value})
        r = plc.read("MyAOI.Setpoint")
        check("AOI MyAOI.Setpoint read", not r.error and abs(r.value - 42.5) < 1e-5, {"err": r.error, "val": r.value})
        w = plc.write(("MyAOI.Setpoint", 99.9)); r = plc.read("MyAOI.Setpoint")
        check("AOI MyAOI.Setpoint write", not w.error and abs(r.value - 99.9) < 1e-5, {"w": w.error, "back": r.value})
        w = plc.write(("MyAOI.Enable", False)); r = plc.read("MyAOI.Enable")
        check("AOI MyAOI.Enable write", not w.error and bool(r.value) is False, {"w": w.error, "back": r.value})

        # Rows 39-40: multi-service batch read AND batch write
        batch = plc.read("DintArr[0]", "DintArr[1]", "DintArr[2]")
        check("39 batch read",
              all(not t.error for t in batch)
              and [t.value for t in batch] == [1000, 1001, 1002],
              [(t.tag, t.value, t.error) for t in batch])
        res = plc.write(("DintArr[0]", 5000), ("DintArr[1]", 5001), ("DintArr[2]", 5002))
        r = plc.read("DintArr[0]", "DintArr[1]", "DintArr[2]")
        check("40 batch write",
              all(not t.error for t in res)
              and [t.value for t in r] == [5000, 5001, 5002],
              {"res_errs": [t.error for t in res],
               "back":     [t.value for t in r]})

    assert not failures, "pycomm3 round-trip failures:\n" + "\n".join(
        f"  {k}: {v!r}" for k, v in failures.items()
    )
