#!/usr/bin/env python3
"""Inspect scalar buckets in PHP's HTTP superglobals in the isolated FPM lab."""

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    args = parser.parse_args()

    master = int(subprocess.check_output(
        ["docker", "inspect", "-f", "{{.State.Pid}}", args.container], text=True
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
    binary_base = min(bases)
    core = binary_base + symbol(binary, "core_globals")

    descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        read = lambda address, size: os.pread(descriptor, size, address)

        def inspect_array(address: int, depth: int = 0) -> dict[str, object]:
            raw_ht = read(address, 56)
            ar_data = struct.unpack_from("<Q", raw_ht, 16)[0]
            num_used = struct.unpack_from("<I", raw_ht, 24)[0]
            buckets = []
            for bucket_index in range(min(num_used, 4096)):
                bucket_address = ar_data + bucket_index * 32
                raw = read(bucket_address, 32)
                bucket_value, bucket_type = struct.unpack_from("<QI", raw)
                key_pointer = struct.unpack_from("<Q", raw, 24)[0]
                key = ""
                if key_pointer:
                    key_length = struct.unpack("<Q", read(key_pointer + 0x10, 8))[0]
                    if key_length < 4096:
                        key = read(key_pointer + 0x18, key_length).decode(
                            "latin1", "replace"
                        )
                bucket: dict[str, object] = {
                    "index": bucket_index,
                    "address": hex(bucket_address),
                    "value": hex(bucket_value),
                    "type_info": hex(bucket_type),
                    "type": bucket_type & 0xFF,
                    "key": key,
                }
                if bucket_type & 0xFF == 7 and bucket_value and depth < 2:
                    try:
                        bucket["array"] = inspect_array(bucket_value, depth + 1)
                    except (OSError, struct.error) as exc:
                        bucket["array_error"] = str(exc)
                buckets.append(bucket)
            return {"ar_data": hex(ar_data), "num_used": num_used, "buckets": buckets}

        names = ("POST", "GET", "COOKIE", "SERVER", "ENV", "FILES")
        result: dict[str, object] = {"pid": pid, "core_globals": hex(core)}
        for index, name in enumerate(names):
            raw_zval = read(core + 344 + index * 16, 16)
            value, type_info = struct.unpack_from("<QI", raw_zval)
            item: dict[str, object] = {
                "zval": hex(core + 344 + index * 16),
                "value": hex(value),
                "type_info": hex(type_info),
                "buckets": [],
            }
            if type_info & 0xFF == 7 and value:
                item.update(inspect_array(value))
            result[name] = item
    finally:
        os.close(descriptor)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
