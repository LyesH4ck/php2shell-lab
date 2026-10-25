#!/usr/bin/env python3
"""Inspect the SAPI header list of the single isolated Apache worker."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    init_pid = int(subprocess.check_output(
        ["docker", "inspect", "-f", "{{.State.Pid}}", args.container], text=True
    ).strip())
    master = subprocess.check_output(
        ["pgrep", "-P", str(init_pid), "-x", "apache2"], text=True
    ).split()
    worker = subprocess.check_output(
        ["pgrep", "-P", master[0], "-x", "apache2"], text=True
    ).split()
    if len(worker) != 1:
        raise RuntimeError(f"expected one worker, got {worker!r}")
    pid = int(worker[0])
    library = f"/proc/{pid}/root/usr/lib/apache2/modules/libphp.so"
    listing = subprocess.check_output(["nm", "-D", library], text=True)
    symbols: dict[str, int] = {}
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] in {"sapi_globals", "ps_globals"}:
            symbols[fields[-1]] = int(fields[0], 16)
    bases = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if "/usr/lib/apache2/modules/libphp.so" not in line:
            continue
        fields = line.split()
        bases.append(int(fields[0].split("-", 1)[0], 16) - int(fields[2], 16))
    base = min(bases)
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        read = lambda address, size: os.pread(fd, size, address)
        sapi = base + symbols["sapi_globals"]
        ps = base + symbols["ps_globals"]
        head, tail, count = struct.unpack("<QQQ", read(sapi + 0xA0, 24))
        nodes = []
        current = head
        seen = set()
        for _ in range(min(count + 3, 32)):
            if not current or current in seen:
                break
            seen.add(current)
            raw = read(current, 32)
            if len(raw) != 32:
                break
            nxt, prev, value, length = struct.unpack("<QQQQ", raw)
            entry = {
                "address": hex(current), "next": hex(nxt), "prev": hex(prev),
                "value": hex(value), "length": length,
            }
            if value > 0x10000 and length < 8192:
                try:
                    entry["value_hex"] = read(value, min(length, 128)).hex()
                except OSError:
                    pass
            nodes.append(entry)
            current = nxt
        result = {
            "pid": pid, "libphp_base": hex(base), "sapi_globals": hex(sapi),
            "ps_globals": hex(ps), "head": hex(head), "tail": hex(tail),
            "count": count, "ps_id": hex(struct.unpack("<Q", read(ps + 16, 8))[0]),
            "nodes": nodes,
        }
    finally:
        os.close(fd)
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
