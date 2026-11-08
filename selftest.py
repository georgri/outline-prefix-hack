#!/usr/bin/env python3
"""Checks Outline-prefix, plain, and Happ-style handshakes against HOST:PORT.

Usage: selftest.py HOST PORT < secret
Reads one Shadowsocks password (chacha20-ietf-poly1305) from stdin.
"""
import hashlib, os, socket, struct, sys, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = bytes([0x16, 0x03, 0x01, 0x00, 0xa8, 0x01, 0x01])


def evp(password, n):
    prev, out = b"", b""
    while len(out) < n:
        prev = hashlib.md5(prev + password).digest()
        out += prev
    return out[:n]


def subkey(master, salt):
    return HKDF(algorithm=hashes.SHA1(), length=32, salt=salt, info=b"ss-subkey").derive(master)


def chunk(key, payload):
    a = ChaCha20Poly1305(key)
    return a.encrypt((0).to_bytes(12, "little"), struct.pack("!H", len(payload)), None) + \
        a.encrypt((1).to_bytes(12, "little"), payload, None)


def once(host, port, master, mode):
    salt = PREFIX + os.urandom(25) if mode == "outline-prefix" else os.urandom(32)
    req = b"\x03\x0bexample.com" + struct.pack("!H", 80) + b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
    body = salt + chunk(subkey(master, salt), req)
    t = time.time()
    s = socket.create_connection((host, port), 8)
    s.settimeout(8)
    if mode == "happ-prefix":
        s.sendall(PREFIX + body)
    elif mode == "happ-split":
        s.sendall(PREFIX)
        time.sleep(0.3)
        s.sendall(body)
    else:
        s.sendall(body)
    buf = b""
    try:
        while len(buf) < 300:
            b = s.recv(4096)
            if not b:
                break
            buf += b
    except OSError:
        pass
    s.close()
    ok = False
    if len(buf) > 60:
        a = ChaCha20Poly1305(subkey(master, buf[:32]))
        try:
            n = struct.unpack("!H", a.decrypt((0).to_bytes(12, "little"), buf[32:50], None))[0]
            ok = a.decrypt((1).to_bytes(12, "little"), buf[50:50 + n + 16], None).startswith(b"HTTP/")
        except Exception:
            pass
    return ok, time.time() - t


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    master = evp(sys.stdin.readline().strip().encode(), 32)
    failed = 0
    for mode in ("outline-prefix", "plain", "happ-prefix", "happ-split"):
        ok, dt = once(host, port, master, mode)
        failed += not ok
        print(f"{mode:15} {'OK' if ok else 'FAIL'} {dt:.2f}s")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
