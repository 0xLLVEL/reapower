#!/usr/bin/env python3
"""Capture the raw response from the real Madium auth server.

Run this to see exactly what auth.getmadium.xyz replies with, for any endpoint, any
credentials. Nothing is patched here - this talks to the real server over TLS exactly
like the client does.

Usage
-----
    python capture_real.py --endpoint account --username <user> --password "<password>"
    python capture_real.py --endpoint secure --token "<token>"

Endpoints
---------
    account   POST /account/auth          body {"login","password","hwid","nonce"}
    secure    POST /keys/auth/secure      header Authorization: Bearer <token>

HWID is derived the same way the client derives it: MachineGuid from
HKLM\\SOFTWARE\\Microsoft\\Cryptography combined with %LOCALAPPDATA%\\Madium\\hwid_seed.bin.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
import urllib.error
import urllib.request

try:
    import winreg
except ImportError:
    winreg = None

AUTH = "https://auth.getmadium.xyz"


def machine_guid() -> str:
    if winreg is None:
        return ""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as key:
            return str(winreg.QueryValueEx(key, "MachineGuid")[0])
    except OSError:
        return ""


def hwid_seed() -> bytes:
    path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Madium", "hwid_seed.bin")
    if os.path.exists(path):
        with open(path, "rb") as handle:
            return handle.read()
    return b""


def compute_hwid() -> str:
    guid = machine_guid()
    seed = hwid_seed()
    material = guid.encode("utf-8")
    if seed:
        material = guid.encode("utf-8") + seed
    return hashlib.sha256(material).hexdigest()


def raw_post(url: str, body: dict, headers: dict):
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "Madium/2.6.3")
    for name, value in headers.items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()
    except Exception as exc:
        return None, {}, str(exc).encode()


def show(status, headers, body):
    print("status   {}".format(status))
    print("headers")
    for name, value in headers.items():
        print("  {}: {}".format(name, value))
    print("body")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        print("  <binary {} bytes>".format(len(body)))
        return
    print(text)
    try:
        parsed = json.loads(text)
    except ValueError:
        return
    print("parsed keys  {}".format(sorted(parsed.keys())))
    for key in ("status", "reason", "alg", "expiresAt", "issuedAt", "timestamp"):
        if key in parsed:
            print("  {:<10} {}".format(key, parsed[key]))


def main():
    parser = argparse.ArgumentParser(description="capture the real Madium auth server")
    parser.add_argument("--endpoint", choices=("account", "secure"), default="account")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--token", default="")
    parser.add_argument("--hwid", default="")
    parser.add_argument("--nonce", default="")
    args = parser.parse_args()

    hwid = args.hwid or compute_hwid()
    nonce = args.nonce or uuid.uuid4().hex

    print("=" * 76)
    print("endpoint     {}".format(args.endpoint))
    print("machine guid {}".format(machine_guid()))
    print("hwid         {}".format(hwid))
    print("nonce        {}".format(nonce))
    print("=" * 76)

    if args.endpoint == "account":
        url = AUTH + "/account/auth"
        body = {"login": args.username, "password": args.password,
                "hwid": hwid, "nonce": nonce}
        headers = {}
    else:
        url = AUTH + "/keys/auth/secure"
        body = {"hwid": hwid, "nonce": nonce}
        headers = {"Authorization": "Bearer " + args.token}

    print("POST {}  headers={}".format(url, headers))
    print("body    {}".format(json.dumps(body)))
    print("-" * 76)
    status, response_headers, response_body = raw_post(url, body, headers)
    show(status, response_headers, response_body)


if __name__ == "__main__":
    main()
