"""Reconstruct the pristine Madium.exe from a patched one.

The patch touches a known, bounded set of bytes: six two-byte code sites, the 26-byte
auth host string, its 8-byte length field and the 32-byte pinned Ed25519 key. Writing
the original values back over a patched file must reproduce the pristine sha256 exactly -
which is the proof that the patch is the only thing that differs.

    python rebuild_pristine.py <patched.exe> <out.exe>
"""

import hashlib
import shutil
import sys

PRISTINE_SHA = "ad1daac9f09763fb6632df5f92c76073e3c02cb4766917277e6469f9fb9f0a7a"

ORIGINAL_HOST = b"https://auth.getmadium.xyz"
ORIGINAL_PUBKEY = bytes.fromhex("23572ca500262e26595b8667682fcaecb2a33264e1b242c11684333f46080125")

# name, file offset, original bytes
SITES = [
    ("expiry", 0x22231E, bytes([0x7E, 0x70])),
    ("hwid",   0x222207, bytes([0x74, 0x2E])),
    ("clock",  0x22227A, bytes([0x72, 0x71])),
    ("status", 0x21EB1F, bytes([0x74, 0x28])),
    ("sig1",   0x21E945, bytes([0x74, 0x2B])),
    ("sig2",   0x2221D1, bytes([0x74, 0x4D])),
]
HOST_OFFSET = 0xB2FB94
HOST_LEN_OFFSET = 0xB2FBB8
PUBKEY_OFFSET = 0xB2FF16


def main():
    if len(sys.argv) < 3:
        print("usage: rebuild_pristine.py <patched.exe> <out.exe>")
        return 2
    src, dst = sys.argv[1], sys.argv[2]

    data = bytearray(open(src, "rb").read())
    print("source  {}  sha256 {}".format(src, hashlib.sha256(data).hexdigest()))

    for name, off, original in SITES:
        got = bytes(data[off:off + 2])
        if got != original:
            print("  restore {:<7} 0x{:06X}  {} -> {}".format(name, off, got.hex(), original.hex()))
            data[off:off + 2] = original

    current_host = bytes(data[HOST_OFFSET:HOST_OFFSET + 26]).split(b"\x00")[0]
    if current_host != ORIGINAL_HOST:
        print("  restore host    0x{:06X}  {} -> {}".format(
            HOST_OFFSET, current_host.decode("ascii", "replace"), ORIGINAL_HOST.decode()))
        data[HOST_OFFSET:HOST_OFFSET + 26] = ORIGINAL_HOST + b"\x00" * (26 - len(ORIGINAL_HOST))
    host_len = int.from_bytes(data[HOST_LEN_OFFSET:HOST_LEN_OFFSET + 8], "little")
    if host_len != len(ORIGINAL_HOST):
        print("  restore hostlen 0x{:06X}  {} -> {}".format(HOST_LEN_OFFSET, host_len, len(ORIGINAL_HOST)))
        data[HOST_LEN_OFFSET:HOST_LEN_OFFSET + 8] = len(ORIGINAL_HOST).to_bytes(8, "little")

    current_pub = bytes(data[PUBKEY_OFFSET:PUBKEY_OFFSET + 32])
    if current_pub != ORIGINAL_PUBKEY:
        print("  restore pubkey  0x{:06X}  {} -> {}".format(
            PUBKEY_OFFSET, current_pub.hex(), ORIGINAL_PUBKEY.hex()))
        data[PUBKEY_OFFSET:PUBKEY_OFFSET + 32] = ORIGINAL_PUBKEY

    out = bytes(data)
    digest = hashlib.sha256(out).hexdigest()
    print("\nrebuilt  sha256 {}".format(digest))
    if digest != PRISTINE_SHA:
        print("MISMATCH - expected {}".format(PRISTINE_SHA))
        print("the source file carries changes outside the eight known sites")
        return 1
    open(dst, "wb").write(out)
    print("written {} - matches the pristine build exactly".format(dst))
    return 0


if __name__ == "__main__":
    sys.exit(main())
