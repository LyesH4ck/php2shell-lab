#!/usr/bin/env python3
"""Inspect the SAPI header list of the isolated PHP-FPM lab child."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import subprocess


def symbol(binary: str, name: str) -> int:
    output = subprocess.check_output(["nm", "-D", binary], text=True)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] == name:
            return int(fields[0], 16)
    raise RuntimeError(f"missing dynamic symbol {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    master = int(
        subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Pid}}", args.container],
            text=True,
        ).strip()
    )
    children = subprocess.check_output(
        ["pgrep", "-P", str(master), "-x", "php-fpm"], text=True
    ).split()
    if len(children) != 1:
        raise RuntimeError(f"expected one FPM child, got {children!r}")
    pid = int(children[0])
    binary = f"/proc/{pid}/root/usr/local/sbin/php-fpm"
    candidates = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if "/usr/local/sbin/php-fpm" not in line:
            continue
        fields = line.split()
        candidates.append(
            int(fields[0].split("-", 1)[0], 16) - int(fields[2], 16)
        )
    if not candidates:
        raise RuntimeError("php-fpm mapping missing")
    base = min(candidates)
    sapi = base + symbol(binary, "sapi_globals")
    ps = base + symbol(binary, "ps_globals")
    descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        read = lambda address, size: os.pread(descriptor, size, address)
        head, tail, count = struct.unpack("<QQQ", read(sapi + 0xA0, 24))
        nodes = []
        current = head
        seen = set()
        for _ in range(min(count + 3, 32)):
            if not current or current in seen:
                break
            seen.add(current)
            nxt, prev, value, length = struct.unpack("<QQQQ", read(current, 32))
            entry = {
                "address": hex(current),
                "next": hex(nxt),
                "prev": hex(prev),
                "value": hex(value),
                "length": length,
            }
            if value > 0x10000 and length < 8192:
                entry["value_hex"] = read(value, min(length, 128)).hex()
            nodes.append(entry)
            current = nxt
        main_heap = head & ~0x1FFFFF if head else 0
        result = {
            "pid": pid,
            "php_fpm_base": hex(base),
            "sapi_globals": hex(sapi),
            "ps_globals": hex(ps),
            "head": hex(head),
            "tail": hex(tail),
            "count": count,
            "main_heap": hex(main_heap),
            "ps_id": hex(struct.unpack("<Q", read(ps + 16, 8))[0]),
            "nodes": nodes,
            "fpm_chain_regions": {
                "writer": read(main_heap + 0x57190, 64).hex() if main_heap else "",
                "dtor": read(main_heap + 0x8B000, 128).hex() if main_heap else "",
                "entries": read(main_heap + 0x96000, 64).hex() if main_heap else "",
            },
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

