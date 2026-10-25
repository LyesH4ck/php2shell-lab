#!/usr/bin/env python3
"""Inspect the PHP 8.3.21 terminal reclaim without dispatching callbacks."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import subprocess


def one_worker(container: str) -> int:
    init_pid = int(
        subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Pid}}", container], text=True
        ).strip()
    )
    masters = subprocess.check_output(
        ["pgrep", "-P", str(init_pid), "-x", "apache2"], text=True
    ).split()
    workers = subprocess.check_output(
        ["pgrep", "-P", masters[0], "-x", "apache2"], text=True
    ).split()
    if len(workers) != 1:
        raise RuntimeError(f"expected one worker, got {workers!r}")
    return int(workers[0])


def symbol_value(pid: int, name: str) -> int:
    library = f"/proc/{pid}/root/usr/lib/apache2/modules/libphp.so"
    for line in subprocess.check_output(["nm", "-D", library], text=True).splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] == name:
            return int(fields[0], 16)
    raise RuntimeError(f"symbol missing: {name}")


def library_base(pid: int) -> int:
    candidates = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if "/usr/lib/apache2/modules/libphp.so" not in line:
            continue
        fields = line.split()
        candidates.append(int(fields[0].split("-", 1)[0], 16) - int(fields[2], 16))
    if not candidates:
        raise RuntimeError("libphp mapping missing")
    return min(candidates)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--main-heap", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--expected-htdata", type=lambda value: int(value, 0))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    pid = one_worker(args.container)
    base = library_base(pid)
    ps_globals = base + symbol_value(pid, "ps_globals")
    descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        read = lambda address, size: os.pread(descriptor, size, address)
        # Measured from the pinned PHP 8.3.21 headers.
        http_raw = read(ps_globals + 336, 16)
        http_pointer, http_type = struct.unpack_from("<QI", http_raw)
        stale_raw = read(http_pointer, 40) if http_pointer else b""
        fake_reference = False
        referenced_htdata = None
        if len(stale_raw) == 40:
            refcount, type_info, target, zval_type, tail = struct.unpack_from(
                "<IIQQQ", stale_raw
            )
            fake_reference = (
                refcount == 1
                and type_info == 10
                and zval_type == 0x307
                and tail == 0
            )
            referenced_htdata = target

        chunk = read(args.main_heap, 0x200000)
        candidates = []
        for offset in range(24, len(chunk) - 167, 8):
            refcount, type_info = struct.unpack_from("<II", chunk, offset - 24)
            length = struct.unpack_from("<Q", chunk, offset - 8)[0]
            if refcount != 1 or type_info != 0x16 or length != 167:
                continue
            gc_refcount, gc_type = struct.unpack_from("<II", chunk, offset)
            marker = struct.unpack_from("<Q", chunk, offset + 0x30)[0]
            if gc_refcount == 1 and gc_type == 7 and marker == 0x1111111111111111:
                candidates.append(
                    {
                        "address": hex(args.main_heap + offset),
                        "offset": hex(offset),
                    }
                )
        result = {
            "pid": pid,
            "libphp_base": hex(base),
            "ps_globals": hex(ps_globals),
            "http_session_vars_pointer": hex(http_pointer),
            "http_session_vars_type": hex(http_type),
            "http_session_vars_raw": http_raw.hex(),
            "stale_raw": stale_raw.hex(),
            "fake_reference_hit": fake_reference,
            "referenced_htdata": (
                hex(referenced_htdata) if referenced_htdata is not None else None
            ),
            "expected_htdata": (
                hex(args.expected_htdata) if args.expected_htdata is not None else None
            ),
            "expected_htdata_matches": (
                referenced_htdata == args.expected_htdata
                if args.expected_htdata is not None
                else None
            ),
            "live_hash_tables": candidates,
        }
    finally:
        os.close(descriptor)

    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
