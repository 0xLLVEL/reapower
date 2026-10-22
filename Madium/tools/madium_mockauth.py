#!/usr/bin/env python3
"""Madium local auth server - shape-corrected build.

Response shape was recovered from Madium.exe bytecode, not guessed:

  0x1402228bd  map_get("error")        -> key MUST exist
  0x1402228d3  byte[0] == 1            -> must be a bool (serde_json tag 1)
  0x1402228d8  byte[1] == 0            -> must be false, else "Sign-in failed"
  0x140222969  map_get("message")      -> session object lives HERE
  0x14022298a  byte[0] == 5            -> message must be an object (serde_json tag 5)
  0x1402229ce  map_get("alg")          -> read from message, must equal "Ed25519"
  0x14021fbf6  map_get("signature")    -> read from message
  0x140222de2  map_get("hwid")         -> read from message
  0x140222e46  map_get("issuedAt")     -> read from message
  0x140222f01  map_get("expiresAt")    -> read from message
  0x140222f2f  map_get("token")        -> read from message

So /account/auth answers:
    {"error": false, "message": { ...session... }}

and /keys/auth/secure answers the flat verdict the real server returns:
    {"status","nonce","hwid","timestamp","issuedAt","expiresAt","reason","alg","signature"}

The signature covers the canonical JSON of the signed object with "alg" and "signature"
removed, keys sorted, compact separators. That rule was cracked and verified against a
real server-signed verdict.

Success signal: after a good sign-in the client posts /keys/auth/secure, which this
server announces.

Usage
-----
    python madium_mockauth.py --port 8080 --key-pair keypair.json
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    sys.exit("cryptography is required: pip install cryptography")

UNSIGNED_FIELDS = ("alg", "signature")

# Life-cycle state. The client asks for the verdict once per launch and then goes
# quiet, so the endpoint can retire itself once it is no longer needed.
STATE = {"last_request": 0.0, "verdict_served": False}


def canonical_message(payload: dict) -> bytes:
    signed = {k: v for k, v in payload.items() if k not in UNSIGNED_FIELDS}
    return json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(private_key: Ed25519PrivateKey, payload: dict) -> dict:
    out = dict(payload)
    out["alg"] = "Ed25519"
    out["signature"] = base64.b64encode(
        private_key.sign(canonical_message(out))
    ).decode("ascii")
    return out


def load_or_create_keypair(path: str) -> Ed25519PrivateKey:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            material = json.load(handle)
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(material["private"]))
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"private": base64.b64encode(raw).decode("ascii")}, handle, indent=2)
    return private


def public_hex(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return raw.hex()


def iso_now() -> str:
    moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)


class MockAuth(BaseHTTPRequestHandler):
    server_version = "MadiumMockAuth/1.2"
    protocol_version = "HTTP/1.1"

    private_key = None
    expires_days = 3650
    deny = False
    verbose = True
    log_stream = None

    @staticmethod
    def log_message(fmt, *args):
        line = (fmt % args) if args else fmt
        if MockAuth.verbose:
            stream = MockAuth.log_stream or sys.stderr
            stream.write("[mock] " + line + "\n")
            stream.flush()

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_one_request(self):
        STATE["last_request"] = time.time()
        BaseHTTPRequestHandler.handle_one_request(self)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            pass
        try:
            return dict(parse_qsl(raw.decode("utf-8")))
        except Exception:
            return {}

    def do_POST(self):
        route = self.path.split("?")[0].rstrip("/")
        if route.endswith("/account/auth"):
            self._account_auth()
        elif route.endswith("/keys/auth/secure"):
            self._keys_auth_secure()
        else:
            self._catch_all()

    def do_GET(self):
        self._json(200, {"status": "ok", "service": "madium-mock-auth"})

    def _session(self, request: dict, token: str) -> dict:
        now_ms = int(time.time() * 1000)
        expires_ms = now_ms + int(self.expires_days * 24 * 3600 * 1000)
        session = {
            "alg": "Ed25519",
            "signature": "",
            "hwid": str(request.get("hwid", "")),
            "nonce": str(request.get("nonce", "")),
            "issuedAt": now_ms,
            "expiresAt": expires_ms,
            "timestamp": iso_now(),
            "status": "LICENSE_VALID",
            "reason": "",
            "token": token,
            "key": token,
        }
        return sign(self.private_key, session)

    def _account_auth(self):
        request = self._read_json()
        username = str(request.get("login", request.get("username", "")))
        password = str(request.get("password", ""))
        if self.deny:
            self.log_message("sign-in %s denied (forced)", username)
            self._json(200, {"error": True, "message": "You have no time left. Top up on the site."})
            return
        if not password:
            self._json(200, {"error": True, "message": "Username and password are required"})
            return

        token = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")
        session = self._session(request, token)
        body = {"error": False, "message": session}
        self.log_message("sign-in %s accepted", username)
        self.log_message("  root keys: %s", sorted(body.keys()))
        self.log_message("  message keys: %s", sorted(session.keys()))
        self._json(200, body)

    def _keys_auth_secure(self):
        request = self._read_json()
        if not self.headers.get("Authorization"):
            self._json(400, {"error": True, "message": "Authorization header is required"})
            return
        self.log_message("SUCCESS SIGNAL: client requested /keys/auth/secure")
        token = self.headers.get("Authorization", "")
        verdict = self._session(request, token)
        STATE["verdict_served"] = True
        self._json(200, verdict)

    def _catch_all(self):
        request = self._read_json()
        token = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")
        self.log_message("catch-all for %s", self.path)
        self._json(200, {"error": False, "message": self._session(request, token)})


def daemonize(args):
    """Start a detached copy of this server and return immediately.

    The child gets its own handles (DEVNULL), so it never holds a pipe that the
    caller is reading from. Without that, a caller that captures stdout waits for
    the pipe to close and therefore waits for the whole lifetime of the server.
    """
    script = os.path.abspath(__file__)
    child_argv = [sys.executable, script]
    for token in sys.argv[1:]:
        if token == "--daemon":
            continue
        child_argv.append(token)

    creationflags = 0
    if os.name == "nt":
        creationflags = (getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                         | getattr(subprocess, "DETACHED_PROCESS", 0))
    else:
        creationflags = getattr(subprocess, "CREATE_NEW_SESSION", 0)

    child = subprocess.Popen(
        child_argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creationflags,
    )
    if args.pid_file:
        with open(args.pid_file, "w", encoding="ascii") as handle:
            handle.write(str(child.pid))
    return 0


def watchdog(server, idle_timeout: int, exit_after_verdict: bool, stop_event: threading.Event):
    """Retire the endpoint once nobody needs it any more.

    The client asks for its verdict once per launch and then goes quiet, so an
    endpoint that has served the verdict and then sees no traffic for a while is
    no longer part of the running system. An idle timeout does the same without
    waiting for the verdict.
    """
    if idle_timeout <= 0:
        return
    while not stop_event.wait(0.5):
        if exit_after_verdict and not STATE["verdict_served"]:
            continue
        idle = time.time() - STATE["last_request"]
        if idle >= idle_timeout:
            reason = "the verdict was served" if exit_after_verdict else "no traffic"
            MockAuth.log_message("idle for %.0fs (%s) - the endpoint is no longer needed, exiting",
                                 idle, reason)
            server.shutdown()
            return


def main():
    parser = argparse.ArgumentParser(description="Madium local auth server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--key-pair", default="keypair.json")
    parser.add_argument("--expires-days", type=int, default=3650)
    parser.add_argument("--deny", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--log", default="",
                        help="write the log to this file instead of stdout")
    parser.add_argument("--pid-file", default="",
                        help="write the server pid to this file once it is listening")
    parser.add_argument("--daemon", action="store_true",
                        help="start a detached background copy and return immediately")
    parser.add_argument("--idle-timeout", type=int, default=0,
                        help="exit after this many seconds without a request (0 = never)")
    parser.add_argument("--exit-after-verdict", action="store_true",
                        help="exit once the verdict was served and the client went quiet")
    parser.add_argument("--generate-key-only", action="store_true",
                        help="create the keypair if needed, print the public key and exit")
    args = parser.parse_args()

    # Detaching from the parent has to happen before anything else: a caller that
    # captures our stdout waits for the pipe to close, and a long-lived server
    # holding that pipe would keep the caller waiting forever.
    if args.daemon:
        return daemonize(args)

    private = load_or_create_keypair(args.key_pair)
    MockAuth.private_key = private
    MockAuth.expires_days = args.expires_days
    MockAuth.deny = args.deny
    # The request log is always on - it is the only way to see what the client
    # asked for. --quiet only silences the startup banner on the console.
    MockAuth.verbose = True

    pub = public_hex(private)

    if args.generate_key_only:
        print(pub)
        return 0

    # Writing the log to a file lets the caller start this process without
    # holding its stdout pipe open, which would otherwise make the caller wait
    # for the server to exit.
    if args.log:
        MockAuth.log_stream = open(args.log, "a", encoding="utf-8", buffering=1)

    if not args.quiet:
        print("=" * 76)
        print("Madium local auth server  (shape-corrected)")
        print("=" * 76)
        print("listening        http://{}:{}".format(args.host, args.port))
        print("key pair file    {}".format(os.path.abspath(args.key_pair)))
        print()
        print("Ed25519 public key (32 bytes hex):")
        print("    {}".format(pub))
        print()
        print("success signal   a POST to /keys/auth/secure")
        print("=" * 76)
        print()
        sys.stdout.flush()
    else:
        MockAuth.log_message("listening on http://%s:%d", args.host, args.port)
        MockAuth.log_message("key pair file %s", os.path.abspath(args.key_pair))

    server = ThreadingHTTPServer((args.host, args.port), MockAuth)
    STATE["last_request"] = time.time()
    if args.pid_file:
        with open(args.pid_file, "w", encoding="ascii") as handle:
            handle.write(str(os.getpid()))

    idle_timeout = args.idle_timeout
    if args.exit_after_verdict and idle_timeout <= 0:
        idle_timeout = 20
    stop_event = threading.Event()
    watcher = None
    if idle_timeout > 0:
        watcher = threading.Thread(
            target=watchdog,
            args=(server, idle_timeout, args.exit_after_verdict, stop_event),
            daemon=True)
        watcher.start()
        MockAuth.log_message("life cycle: idle timeout %ds%s", idle_timeout,
                             (", exit after the verdict is served" if args.exit_after_verdict else ""))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        if args.pid_file:
            try:
                os.remove(args.pid_file)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
