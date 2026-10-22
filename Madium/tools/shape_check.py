"""Verify the corrected /account/auth response shape against the real server.

The real server's error envelope for a rejected sign-in is:
    {"error": true, "message": "..."}

Madium.exe at 0x1402228bd reads "error" first, checks it is a bool, and only continues
when it is false. It then reads "message" and requires it to be an object (tag 5), and
pulls alg / signature / hwid / issuedAt / expiresAt / token out of that object.

This script checks two things:
  1. the shape the client needs is a superset of what the real server sends
  2. our mock's response satisfies every field the client reads

Usage:  python shape_check.py
"""

import base64
import json
import os
import sys
import time
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = r"C:\Users\ezan\AppData\Local\Madium\Bin\Madium.exe"
PUBKEY_OFF = 0xB2FF16

# Fields the client reads out of the "message" object, with the site that reads them.
CLIENT_READS = {
    "alg": "0x1402229ce",
    "signature": "0x14021fbf6",
    "hwid": "0x140222de2",
    "issuedAt": "0x140222e46",
    "expiresAt": "0x140222f01",
    "token": "0x140222f2f",
}

# Root-level keys the client reads before it opens "message".
ROOT_READS = {
    "error": "0x1402228bd (bool, must be false)",
    "message": "0x140222969 (must be an object)",
}

failures = []


def check(label, condition, detail=""):
    mark = "PASS" if condition else "FAIL"
    if not condition:
        failures.append(label)
    print("  [{}] {}{}".format(mark, label, ("  -> " + detail) if detail else ""))


def canonical(payload: dict) -> bytes:
    signed = {k: v for k, v in payload.items() if k not in ("alg", "signature")}
    return json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main():
    print("=" * 76)
    print("response shape check")
    print("=" * 76)

    print("\n[1] the real server's error envelope shape")
    request = urllib.request.Request(
        "https://auth.getmadium.xyz/account/auth",
        data=json.dumps({"login": "probe", "password": "probe",
                         "hwid": "0" * 64, "nonce": "0" * 32}).encode(),
        method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "Madium/2.6.3")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = response.status
            body = response.read().decode()
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode()
    print("  status {}".format(status))
    print("  body   {}".format(body))
    real = json.loads(body)
    check("real server sends an 'error' key", "error" in real)
    check("real server sends a 'message' key", "message" in real)
    check("real 'error' is a bool", isinstance(real.get("error"), bool))

    print("\n[2] fields the client reads, and where")
    for name, site in sorted(ROOT_READS.items()):
        print("  root    {:<10} {}".format(name, site))
    for name, site in sorted(CLIENT_READS.items()):
        print("  message {:<10} {}".format(name, site))

    print("\n[3] build the response the client expects")
    now_ms = int(time.time() * 1000)
    session = {
        "alg": "Ed25519",
        "signature": "",
        "hwid": "0" * 64,
        "nonce": "a6b8ac44f350844dff4d26459109030f",
        "issuedAt": now_ms,
        "expiresAt": now_ms + 3650 * 24 * 3600 * 1000,
        "timestamp": "2026-10-22T04:34:00.770Z",
        "status": "LICENSE_VALID",
        "reason": "",
        "token": "session-token",
        "key": "session-token",
    }
    body = {"error": False, "message": session}

    check("root has 'error'", "error" in body)
    check("root 'error' is false", body["error"] is False)
    check("root 'message' is an object", isinstance(body["message"], dict))
    for name in CLIENT_READS:
        check("message carries '{}'".format(name), name in session)

    print("\n[4] sign it with a keypair and verify against the patched anchor")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    private = Ed25519PrivateKey.generate()
    message = canonical(session)
    signed = dict(session)
    signed["signature"] = base64.b64encode(private.sign(message)).decode()
    body["message"] = signed

    pub = Ed25519PublicKey.from_public_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    try:
        pub.verify(base64.b64decode(signed["signature"]), canonical(signed))
        check("signature verifies over canonical(message)", True)
    except InvalidSignature:
        check("signature verifies over canonical(message)", False)

    original = open(TARGET, "rb").read()
    anchor = Ed25519PublicKey.from_public_bytes(original[PUBKEY_OFF:PUBKEY_OFF + 32])
    try:
        anchor.verify(base64.b64decode(signed["signature"]), canonical(signed))
        check("anchor rejects the forged signature", False, "it accepted it")
    except InvalidSignature:
        check("anchor rejects the forged signature", True)

    print("\n[5] the exact body to hand the client")
    print(json.dumps(body, indent=2, sort_keys=True))

    print("\n" + "=" * 76)
    if failures:
        print("FAILED {}: {}".format(len(failures), ", ".join(failures)))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
