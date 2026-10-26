#!/usr/bin/env python3
"""Locate the POST BIG bucket in the isolated one-worker FPM lab.

Run while /body-leak.php?hold=N is sleeping after multipart parsing. The BIG
payload begins at the calibrated FBASE, so its zend_string header is FBASE-0x18.
The script finds heap qwords that reference that header and validates the
HashTable Bucket by checking the adjacent zval type and the key "BIG".
"""

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
    parser.add_argument("--fbase", type=lambda value: int(value, 0), default=0x86018)
    parser.add_argument("--scratch", type=lambda value: int(value, 0))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    master = int(subprocess.check_output(
        ["docker", "inspect", "-f", "{{.State.Pid}}", args.container],
        text=True,
    ).strip())
    children = subprocess.check_output(
        ["pgrep", "-P", str(master), "-x", "php-fpm"], text=True
    ).split()
    if len(children) != 1:
        raise RuntimeError(f"expected one FPM child, got {children!r}")
    pid = int(children[0])
    binary = f"/proc/{pid}/root/usr/local/sbin/php-fpm"
    bases = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if "/usr/local/sbin/php-fpm" in line:
            fields = line.split()
            bases.append(int(fields[0].split("-", 1)[0], 16) - int(fields[2], 16))
    base = min(bases)
    sapi = base + symbol(binary, "sapi_globals")
    core = base + symbol(binary, "core_globals")
    basic = base + symbol(binary, "basic_globals")

    descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        read = lambda address, size: os.pread(descriptor, size, address)
        unserialize_data = struct.unpack("<Q", read(basic + 0x358, 8))[0]
        stale_last = struct.unpack("<Q", read(unserialize_data, 8))[0] if unserialize_data else 0
        attack_heap = stale_last & ~0x1FFFFF if stale_last else 0
        header_head = struct.unpack("<Q", read(sapi + 0xA0, 8))[0]
        if header_head:
            main_heap = header_head & ~0x1FFFFF
        else:
            zend_maps = [
                int(line.split("-", 1)[0], 16)
                for line in Path(f"/proc/{pid}/maps").read_text().splitlines()
                if "[anon:zend_alloc]" in line
            ]
            if len(zend_maps) != 1:
                raise RuntimeError(f"cannot identify ZendMM chunk: {zend_maps!r}")
            main_heap = zend_maps[0]
        chunk = read(main_heap, 0x200000)
        # php_core_globals::http_globals begins at +344 on this non-ZTS 8.3.21
        # amd64 build; element zero is PG(http_globals)[TRACK_VARS_POST].
        post_array, post_type = struct.unpack("<QI", read(core + 344, 12))
        if post_type & 0xFF != 7:
            raise RuntimeError(f"POST is not an array: pointer={post_array:#x} type={post_type:#x}")
        post_raw = read(post_array, 56)
        ar_data = struct.unpack_from("<Q", post_raw, 16)[0]
        num_used = struct.unpack_from("<I", post_raw, 24)[0]
        candidates = []
        big_bucket = None
        for index in range(num_used):
            address = ar_data + index * 32
            raw = read(address, 32)
            value, type_info = struct.unpack_from("<QI", raw, 0)
            key_pointer = struct.unpack_from("<Q", raw, 24)[0]
            key = b""
            key_len = 0
            if key_pointer:
                key_len = struct.unpack("<Q", read(key_pointer + 0x10, 8))[0]
                if key_len < 4096:
                    key = read(key_pointer + 0x18, key_len)
            item = {
                "index": index,
                "address": hex(address),
                "offset": hex(address - main_heap),
                "value": hex(value),
                "value_offset": hex(value - main_heap),
                "type_info": hex(type_info),
                "key_pointer": hex(key_pointer),
                "key_len": key_len,
                "key_hex": key.hex(),
            }
            candidates.append(item)
            if key == b"BIG":
                big_bucket = item
        if big_bucket is None:
            raise RuntimeError("BIG bucket not found")
        string_header = int(big_bucket["value"], 16)
        result = {
            "pid": pid,
            "main_heap": hex(main_heap),
            "attack_heap": hex(attack_heap),
            "attack_heap_delta": hex(attack_heap - main_heap),
            "core_globals": hex(core),
            "post_array": hex(post_array),
            "post_ar_data": hex(ar_data),
            "post_num_used": num_used,
            "fbase": hex(args.fbase),
            "big_string_header": hex(string_header),
            "big_data": hex(string_header + 0x18),
            "big_data_offset": hex(string_header + 0x18 - main_heap),
            "big_bucket": big_bucket,
            "big_bucket_attack_offset": hex(int(big_bucket["address"], 16) - attack_heap),
            "candidates": candidates,
        }
        if args.scratch is not None:
            scratch_base = attack_heap or main_heap
            scratch = read(scratch_base + args.scratch, 128)
            result["scratch_offset"] = hex(args.scratch)
            result["scratch_address"] = hex(scratch_base + args.scratch)
            result["scratch_hex"] = scratch.hex()
            result["scratch_qwords"] = [
                hex(value) for value in struct.unpack("<16Q", scratch)
            ]
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
