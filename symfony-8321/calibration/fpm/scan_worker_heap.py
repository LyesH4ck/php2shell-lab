#!/usr/bin/env python3
"""Locate controlled long byte runs in one FPM child's ZendMM main chunk."""

from __future__ import annotations

import argparse
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


def namespace_pid(host_pid: int) -> int:
    for line in Path(f"/proc/{host_pid}/status").read_text().splitlines():
        if line.startswith("NSpid:"):
            return int(line.split()[-1])
    return host_pid


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--namespace-pid", required=True, type=int)
    parser.add_argument("--byte", default="41")
    parser.add_argument("--minimum", type=int, default=4096)
    args = parser.parse_args()

    master = int(
        subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Pid}}", args.container],
            text=True,
        ).strip()
    )
    children = [
        int(item)
        for item in subprocess.check_output(
            ["pgrep", "-P", str(master), "-x", "php-fpm"], text=True
        ).split()
    ]
    matches = [pid for pid in children if namespace_pid(pid) == args.namespace_pid]
    if len(matches) != 1:
        raise RuntimeError(f"namespace PID match failed: {matches!r}")
    pid = matches[0]
    binary = f"/proc/{pid}/root/usr/local/sbin/php-fpm"
    bases = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if "/usr/local/sbin/php-fpm" in line:
            fields = line.split()
            bases.append(int(fields[0].split("-", 1)[0], 16) - int(fields[2], 16))
    base = min(bases)
    sapi = base + symbol(binary, "sapi_globals")
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        head = struct.unpack("<Q", os.pread(fd, 8, sapi + 0xA0))[0]
        main_heap = head & ~0x1FFFFF
        data = os.pread(fd, 0x200000, main_heap)
    finally:
        os.close(fd)

    needle = bytes.fromhex(args.byte)
    if len(needle) != 1:
        raise RuntimeError("--byte must encode exactly one byte")
    runs = []
    start = None
    for offset, value in enumerate(data):
        if value == needle[0]:
            if start is None:
                start = offset
        elif start is not None:
            if offset - start >= args.minimum:
                runs.append((start, offset - start))
            start = None
    if start is not None and len(data) - start >= args.minimum:
        runs.append((start, len(data) - start))

    print(f"host_pid={pid} namespace_pid={args.namespace_pid}")
    print(f"main_heap={main_heap:#x} header_head={head:#x}")
    for offset, length in runs:
        print(f"run offset={offset:#x} length={length:#x}")
    return 0 if runs else 1


if __name__ == "__main__":
    raise SystemExit(main())

