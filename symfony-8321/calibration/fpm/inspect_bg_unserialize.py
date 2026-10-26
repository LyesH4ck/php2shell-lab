#!/usr/bin/env python3
"""Read the stale BG(unserialize) pointers from an isolated FPM lab child."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import subprocess


def symbol(binary: str, name: str) -> int:
    for line in subprocess.check_output(["nm", "-D", binary], text=True).splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] == name:
            return int(fields[0], 16)
    raise RuntimeError(f"missing symbol {name}")


def inspect(container: str) -> dict[str, object]:
    master = int(subprocess.check_output(
        ["docker", "inspect", "-f", "{{.State.Pid}}", container], text=True
    ).strip())
    children = subprocess.check_output(
        ["pgrep", "-P", str(master), "-x", "php-fpm"], text=True
    ).split()
    if len(children) != 1:
        raise RuntimeError(f"expected one FPM child, got {children!r}")
    pid = int(children[0])
    maps = Path(f"/proc/{pid}/maps").read_text().splitlines()
    binary = f"/proc/{pid}/root/usr/local/sbin/php-fpm"
    bases = []
    for line in maps:
        if "/usr/local/sbin/php-fpm" in line:
            fields = line.split()
            bases.append(int(fields[0].split("-", 1)[0], 16) - int(fields[2], 16))
    base = min(bases)
    basic = base + symbol(binary, "basic_globals")

    descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        read = lambda address, size: os.pread(descriptor, size, address)
        data = struct.unpack("<Q", read(basic + 0x358, 8))[0]
        level = struct.unpack("<I", read(basic + 0x360, 4))[0]
        raw = read(data, 64) if data else b""
        if len(raw) >= 24:
            last, first_dtor, last_dtor = struct.unpack_from("<QQQ", raw)
        else:
            last = first_dtor = last_dtor = 0
        main_heap = last & ~0x1FFFFF if last else (data & ~0x1FFFFF if data else 0)
    finally:
        os.close(descriptor)

    offset = lambda pointer: pointer - main_heap if pointer else None
    return {
        "pid": pid,
        "main_heap": hex(main_heap),
        "basic_globals": hex(basic),
        "data": hex(data),
        "data_offset": hex(offset(data)) if data else None,
        "level": level,
        "last": hex(last),
        "last_offset": hex(offset(last)) if last else None,
        "first_dtor": hex(first_dtor),
        "first_dtor_offset": hex(offset(first_dtor)) if first_dtor else None,
        "last_dtor": hex(last_dtor),
        "last_dtor_offset": hex(offset(last_dtor)) if last_dtor else None,
        "raw": raw.hex(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = inspect(args.container)
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
