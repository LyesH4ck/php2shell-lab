#!/usr/bin/env python3
"""Read PHP session globals from an idle worker in a Docker lab container.

Diagnostic calibration only: addresses emitted by this helper must never be
fed to the final HTTP-only exploit.
"""

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

    init_pid = int(
        subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Pid}}", args.container],
            text=True,
        ).strip()
    )
    masters = subprocess.check_output(
        ["pgrep", "-P", str(init_pid), "apache2"], text=True
    ).split()
    if len(masters) != 1:
        raise RuntimeError(f"expected one Apache master, got {masters!r}")
    children = subprocess.check_output(
        ["pgrep", "-P", masters[0], "apache2"], text=True
    ).split()
    if len(children) != 1:
        raise RuntimeError(f"expected one Apache worker, got {children!r}")
    pid = int(children[0])

    map_path = "/usr/lib/apache2/modules/libphp.so"
    file_path = f"/proc/{pid}/root{map_path}"
    bases: list[int] = []
    map_lines: list[str] = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if map_path not in line:
            continue
        map_lines.append(line)
        fields = line.split()
        start = int(fields[0].split("-", 1)[0], 16)
        file_offset = int(fields[2], 16)
        bases.append(start - file_offset)
    if not bases:
        raise RuntimeError("libphp mapping not found")
    libphp_base = min(bases)

    symbol_offset = None
    listing = subprocess.check_output(["nm", "-D", file_path], text=True)
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] == "ps_globals":
            symbol_offset = int(fields[0], 16)
            break
    if symbol_offset is None:
        raise RuntimeError("ps_globals symbol not found")

    # Measured from the exact PHP 8.3.21 headers in the pinned image.
    offsets = {
        "id": 16,
        "mod_data": 96,
        "send_cookie": 376,
        "http_session_vars": 336,
    }
    ps_globals = libphp_base + symbol_offset
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        def read(address: int, size: int) -> bytes:
            value = os.pread(fd, size, address)
            if len(value) != size:
                raise RuntimeError(f"short read at {address:#x}")
            return value

        id_pointer = struct.unpack("<Q", read(ps_globals + offsets["id"], 8))[0]
        result: dict[str, object] = {
            "container": args.container,
            "pid": pid,
            "libphp_base": f"{libphp_base:#x}",
            "ps_globals": f"{ps_globals:#x}",
            "offsets": offsets,
            "id_pointer": f"{id_pointer:#x}",
            "mod_data_pointer": f"{struct.unpack('<Q', read(ps_globals + offsets['mod_data'], 8))[0]:#x}",
            "send_cookie": read(ps_globals + offsets["send_cookie"], 1)[0],
            "http_session_vars_raw": read(
                ps_globals + offsets["http_session_vars"], 16
            ).hex(),
            "maps": map_lines,
        }
        if id_pointer:
            header = read(id_pointer, 24)
            refcount, type_info, string_hash, string_length = struct.unpack(
                "<IIQQ", header
            )
            chunk_base = id_pointer & ~0x1FFFFF
            result["id_zend_string"] = {
                "refcount": refcount,
                "type_info": f"{type_info:#x}",
                "hash": f"{string_hash:#x}",
                "length": string_length,
                "chunk_base": f"{chunk_base:#x}",
                "offset_in_chunk": id_pointer - chunk_base,
                "page_index": (id_pointer - chunk_base) // 4096,
                "offset_in_page": (id_pointer - chunk_base) % 4096,
                "value_hex": read(id_pointer + 24, min(string_length, 128)).hex(),
            }
            chunk_header = read(chunk_base, 64)
            heap_pointer, next_chunk, previous_chunk = struct.unpack_from(
                "<QQQ", chunk_header, 0
            )
            free_pages, free_tail, chunk_number = struct.unpack_from(
                "<III", chunk_header, 24
            )
            result["id_chunk"] = {
                "heap": f"{heap_pointer:#x}",
                "next": f"{next_chunk:#x}",
                "previous": f"{previous_chunk:#x}",
                "free_pages": free_pages,
                "free_tail": free_tail,
                "number": chunk_number,
            }
            if heap_pointer:
                result["zend_mm_heap"] = {
                    "use_custom_heap": struct.unpack(
                        "<i", read(heap_pointer, 4)
                    )[0],
                    "size": struct.unpack("<Q", read(heap_pointer + 0x10, 8))[0],
                    "real_size": struct.unpack(
                        "<Q", read(heap_pointer + 0x118, 8)
                    )[0],
                    "limit": struct.unpack(
                        "<Q", read(heap_pointer + 0x128, 8)
                    )[0],
                    "main_chunk": f"{struct.unpack('<Q', read(heap_pointer + 0x140, 8))[0]:#x}",
                    "cached_chunks": f"{struct.unpack('<Q', read(heap_pointer + 0x148, 8))[0]:#x}",
                    "chunks_count": struct.unpack(
                        "<i", read(heap_pointer + 0x150, 4)
                    )[0],
                    "cached_chunks_count": struct.unpack(
                        "<i", read(heap_pointer + 0x158, 4)
                    )[0],
                }
    finally:
        os.close(fd)

    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
