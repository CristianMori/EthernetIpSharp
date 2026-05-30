"""
Test EipSim Logix simulator with pycomm3.
Start the simulator first: dotnet run --project tests/LogixHost/
"""
import sys
import struct
from pycomm3 import CIPDriver
from pycomm3.cip import Services, ClassCode

TARGET = "127.0.0.1"
PASSED = 0
FAILED = 0

def test(name, func):
    global PASSED, FAILED
    try:
        func()
        print(f"  PASS: {name}")
        PASSED += 1
    except Exception as e:
        print(f"  FAIL: {name} -- {e}")
        FAILED += 1

def main():
    global PASSED, FAILED

    print(f"Connecting to {TARGET}...")
    plc = CIPDriver(TARGET)
    plc.open()
    print(f"Connected. Session: {plc._session}")
    print()

    print("=== Identity (via Unconnected Send) ===")
    test("GetAttributeAll on Identity", lambda: check_identity(plc))

    print("\n=== Tag Read (via Unconnected Send + symbolic path) ===")
    test("Read DINT tag 'rate'", lambda: check_read_dint(plc))
    test("Read REAL tag 'temperature'", lambda: check_read_real(plc))

    print("\n=== Tag Write ===")
    test("Write and read back DINT", lambda: check_write_dint(plc))
    test("Write and read back REAL", lambda: check_write_real(plc))

    plc.close()

    print(f"\n=== Results: {PASSED} passed, {FAILED} failed ===")
    sys.exit(1 if FAILED > 0 else 0)


def send_unconnected(plc, service_code, path_bytes, request_data=b""):
    """Send a CIP request via Unconnected Send to Connection Manager."""
    # Build the inner MR request: service + path_size_words + path + data
    path_words = len(path_bytes) // 2
    mr_request = bytes([service_code, path_words]) + path_bytes + request_data

    # Wrap in Unconnected Send (0x52) to Connection Manager (class 0x06, instance 1)
    # Format: priority(1) + timeout(1) + msg_length(UINT) + mr_request + [pad] + route_path_size(1) + reserved(1)
    msg_len = len(mr_request)
    pad = b"\x00" if msg_len % 2 != 0 else b""
    ucmm_data = bytes([0x0A, 0x05]) + struct.pack("<H", msg_len) + mr_request + pad + b"\x00\x00"

    # Send via generic_message to Connection Manager
    resp = plc.generic_message(
        service=0x52,
        class_code=0x06,
        instance=1,
        request_data=ucmm_data,
        connected=False,
        unconnected_send=False,  # We're building it ourselves
        route_path=False,
        name="ucmm",
    )
    return resp


def check_identity(plc):
    # GetAttributeAll on Identity class 0x01, instance 1
    path = bytes([0x20, 0x01, 0x24, 0x01])
    resp = send_unconnected(plc, 0x01, path)
    print(f"    response error: {resp.error}")
    print(f"    response value type: {type(resp.value)}")
    assert resp.error is None, f"Error: {resp.error}"


def check_read_dint(plc):
    path = build_symbolic_path("rate")
    resp = send_unconnected(plc, 0x4C, path, b"\x01\x00")
    assert resp.error is None, f"Error: {resp.error}"
    data = bytes(resp.value) if resp.value else b""
    tag_type = int.from_bytes(data[0:2], "little")
    value = int.from_bytes(data[2:6], "little", signed=True)
    print(f"    tag_type=0x{tag_type:04X}, value={value}")
    assert tag_type == 0x00C4, f"Expected DINT 0xC4, got 0x{tag_type:04X}"
    assert value == 534, f"Expected 534, got {value}"


def check_read_real(plc):
    path = build_symbolic_path("temperature")
    resp = send_unconnected(plc, 0x4C, path, b"\x01\x00")
    assert resp.error is None, f"Error: {resp.error}"
    data = bytes(resp.value)
    tag_type = int.from_bytes(data[0:2], "little")
    value = struct.unpack("<f", data[2:6])[0]
    print(f"    tag_type=0x{tag_type:04X}, value={value}")
    assert tag_type == 0x00CA, f"Expected REAL 0xCA, got 0x{tag_type:04X}"
    assert abs(value - 72.5) < 0.01, f"Expected 72.5, got {value}"


def check_write_dint(plc):
    path = build_symbolic_path("rate")
    write_data = struct.pack("<HHI", 0x00C4, 1, 9999)
    resp = send_unconnected(plc, 0x4D, path, write_data)
    assert resp.error is None, f"Write error: {resp.error}"

    # Read back
    resp = send_unconnected(plc, 0x4C, path, b"\x01\x00")
    assert resp.error is None, f"Readback error: {resp.error}"
    data = bytes(resp.value)
    value = int.from_bytes(data[2:6], "little", signed=True)
    print(f"    wrote 9999, read back {value}")
    assert value == 9999, f"Expected 9999, got {value}"

    # Restore
    send_unconnected(plc, 0x4D, path, struct.pack("<HHI", 0x00C4, 1, 534))


def check_write_real(plc):
    path = build_symbolic_path("temperature")
    write_data = struct.pack("<HHf", 0x00CA, 1, 100.0)
    resp = send_unconnected(plc, 0x4D, path, write_data)
    assert resp.error is None, f"Write error: {resp.error}"

    resp = send_unconnected(plc, 0x4C, path, b"\x01\x00")
    assert resp.error is None, f"Readback error: {resp.error}"
    data = bytes(resp.value)
    value = struct.unpack("<f", data[2:6])[0]
    print(f"    wrote 100.0, read back {value}")
    assert abs(value - 100.0) < 0.01, f"Expected 100.0, got {value}"

    # Restore
    send_unconnected(plc, 0x4D, path, struct.pack("<HHf", 0x00CA, 1, 72.5))


def build_symbolic_path(name):
    name_bytes = name.encode("ascii")
    pad = b"\x00" if len(name_bytes) % 2 != 0 else b""
    return b"\x91" + bytes([len(name_bytes)]) + name_bytes + pad


if __name__ == "__main__":
    main()
