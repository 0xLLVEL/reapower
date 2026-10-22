# Madium - Entitlement Unlock (native x64 patch + local auth endpoint)

Local patcher for the Madium client (Windows desktop app, Tauri 2.11.4 + Rust) that removes
the entitlement gate: the client accepts a locally issued session instead of asking the
licence server for one, so the workbench is reachable without a live subscription.

Everything here operates on your own installation, on disk. It is an analysis of a shipped
native binary, a byte-level patch of it, and a small local server that answers the two
endpoints the client calls: **eight sites across the PE, 24 bytes written**.

The server is not bypassed - it is *replaced*. The client is redirected to a listener on
loopback that signs its own verdicts with a keypair whose private half never leaves disk.

---

## Table of contents

1. [Current version / verified build](#1-current-version--verified-build)
2. [TL;DR - install](#2-tldr--install)
3. [What it does / what it does NOT do](#3-what-it-does--what-it-does-not-do)
4. [How Madium's entitlement actually works](#4-how-madiums-entitlement-actually-works)
   - [The two endpoints](#the-two-endpoints)
   - [The verdict chain](#the-verdict-chain)
   - [The trust anchor](#the-trust-anchor)
   - [The canonical signed message](#the-canonical-signed-message)
   - [The response shape](#the-response-shape)
5. [The eight patches](#5-the-eight-patches)
6. [Verification](#6-verification)
7. [Exit codes](#7-exit-codes)
8. [Limits](#8-limits)
9. [The analysis tooling](#9-the-analysis-tooling)

---

## 1. Current version / verified build

| field | value |
|---|---|
| target | `%LOCALAPPDATA%\Madium\Bin\Madium.exe` |
| software version | 2.6.3 (installer 1.1.0) |
| size | 13,352,448 bytes |
| machine | `0x8664` (x86-64) |
| image base | `0x140000000` |
| sections | 6 |
| toolchain | Rust, `rustc ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96` (from the panic path strings) |
| runtime | Tauri 2.11.4, reqwest 0.13.4, hyper-rustls 0.27.9, tokio-rustls 0.26.4, rustls 0.23.41, curve25519-dalek 4.1.3, sha2 0.11.0 |
| sha256 pristine | `ad1daac9f09763fb6632df5f92c76073e3c02cb4766917277e6469f9fb9f0a7a` |
| bytes written | **24**, across 8 sites (6 code sites of 2 bytes, 32-byte key, 26-byte host + 8-byte length) |
| companion | `Madium.dll` (the executor payload) and `RobloxPlayerBeta.dll` are fetched at runtime from `cdn.getmadium.me` - **unauthenticated**, HTTP 206, `MZ` header |

A different Madium build gets a different hash. The patcher refuses to touch a build it has
not seen; see [8. Limits](#8-limits).

---

## 2. TL;DR - install

```
install.cmd          (backs up Madium.exe, patches, generates a keypair, starts the endpoint)
patch-now.cmd        (re-patch after an Madium update - manual mode, no task, no watcher)
uninstall.cmd        (restores the pristine Madium.exe, stops the endpoint, removes the keypair)
```

`install.cmd` self-requests UAC. Nothing is scheduled, nothing is watched.

Requires Python 3 with `cryptography` installed (`pip install cryptography`) - the local
endpoint signs with Ed25519.

After install, open Madium and sign in with **any** credentials. The endpoint must stay
running while the client is open.

### What the installer does, in order

1. makes sure the Ed25519 keypair is complete - a public key whose private half was deleted
   leaves the endpoint unable to sign, and the client then rejects every verdict, so a
   half-present keypair is regenerated;
2. patches the client with `-Profile full` (all six code sites), the auth host redirect and
   the pinned key;
3. **re-reads the patched file from disk and checks every component**: six byte sites in the
   patched state, the auth host redirected, the host length field readable, the pinned key
   readable. If any of them is missing the installer exits with code 5 and reports which
   one - it never reports success on a partial patch;
4. starts the local endpoint detached, waits for its pid file and probes the port before
   declaring the install done;
5. keeps a backup that holds the *pristine* bytes. Re-patching an already-patched binary
   would otherwise leave a "backup" that is the patched file, which makes restore useless -
   a backup whose hash is not the pristine one is moved aside to `.bak.stale`.

### Running the patcher by hand

Every option accepts `-name`, `--name` and the bare `name`; PowerShell forwards all three to
a native executable unchanged.

```powershell
# 1. generate the keypair and print the public key
python tools\madium_mockauth.py --port 8080 --key-pair keypair.json --generate-key-only

# 2. patch the client (copy the public key from step 1)
.\tools\madium_unlock.exe "$env:LOCALAPPDATA\Madium\Bin\Madium.exe" `
  --in-place --profile full --redirect 127.0.0.1:8080 --pubkey <PUBLICKEY>

# 3. start the endpoint
python tools\madium_mockauth.py --port 8080 --key-pair keypair.json
```

`--list` and `--verify` only read the file and always exit 0 - including for a binary that
is already patched, which legitimately hashes differently. Re-patching an already-patched
binary is allowed: the per-site byte assertions decide, not the hash.

The endpoint can also be started detached, which is what the installer does:

```powershell
python tools\madium_mockauth.py --port 8080 --key-pair keypair.json `
  --quiet --log state\mockauth.log --daemon --pid-file state\mockauth.pid
```

`--daemon` spawns a copy of the server with its own handles and writes that copy's pid to
the pid file. Without it the server inherits the caller's stdout, and a caller that
captures that output waits for the pipe to close - which means waiting for the whole
lifetime of the server.

---

## 3. What it does / what it does NOT do

**Does** - forces the client-side verdict chain to accept:

- the `expires_at` comparison no longer aborts the verdict;
- the `hwid` device binding always continues;
- the `issuedAt` clock-skew window is always accepted;
- the `status` field is always taken on the accept branch;
- both Ed25519 verification *results* are ignored;
- the pinned Ed25519 verifying key is replaced with a keypair you control;
- the auth host is redirected to `http://127.0.0.1:8080`, and a local listener answers both
  auth endpoints with signed verdicts.

**Does not:**

- **Contact the licence server.** The client is pointed at loopback; `auth.getmadium.xyz` is
  never reached from the patched binary.
- **Forge anything against the real server.** The signature is checked by the client against
  a key that now lives in the patch, not by the vendor. The vendor's own verdicts are
  rejected by the patched binary, because the pinned key no longer matches theirs.
- **Touch the payload.** `Madium.dll` and `RobloxPlayerBeta.dll` are fetched by the client
  from the public CDN and are not modified, intercepted or cached here. Their SHA-256 is
  checked by the client against `cdn.getmadium.me/manifest.json` and that check still runs.
- **Modify the WebView2 frontend.** The gate is enforced in Rust; the `LicenseStatus` struct
  (`expires_at`, `has_token`) that the frontend renders is produced by the patched code.
- **Run in the background.** No service, no scheduled task, no injector, no driver. The
  endpoint is a plain `python` process you can see and kill.

---

## 4. How Madium's entitlement actually works

The relevant surface is all inside `Madium.exe`, and it is native x64 - no metadata, no
method names, no IL. Everything below was established by static disassembly of the shipped
binary plus live probes against the real service.

### The two endpoints

```
POST https://auth.getmadium.xyz/account/auth
     body   {"login": ..., "password": ..., "hwid": ..., "nonce": ...}
     200    {"error": true, "message": "..."}      on rejection
     200    {"error": false, "message": { ... }}   on acceptance

POST https://auth.getmadium.xyz/keys/auth/secure
     header Authorization: Bearer <session token>
     body   {"hwid": ..., "nonce": ...}
     200    {"status", "nonce", "hwid", "timestamp", "issuedAt", "expiresAt",
             "reason", "alg", "signature"}
```

The entitlement decision itself is **server-side**. Probing the live service with correct
and incorrect credentials separates the two failure modes cleanly:

| probe | response |
|---|---|
| correct credentials | `402` `{"error":true,"message":"You have no time left. Top up on the site."}` |
| **wrong password** | `401` `{"error":true,"message":"Wrong username or password"}` |
| correct credentials + **random hwid** | `402` (same as the first row) |

Wrong password gives 401 and correct password gives 402, so the credential check passes and
the *entitlement* check then refuses - before the server signs anything. The random-hwid row
gives the same 402, so entitlement is evaluated ahead of the device binding. The server
never issues a verdict for an expired account, which is why a client-side patch alone
cannot open the gate: there is no verdict to accept.

### The verdict chain

The client re-evaluates a verdict twice - once for a fresh sign-in, once for a cached
session. Both paths are the same shape, and both were located by xref from the string
constants:

```
  alg == "Ed25519"                 0x1402229EB   else -> "Madium sent an unsigned session"
  decode the session object        0x140222D44   else -> "Madium sent an invalid session"
  Ed25519 verify                   0x14021FBC0   else -> "Madium's session signature did not verify"
  hwid == local hwid               0x140222E00   else -> "Madium answered for a different device"
  |now - issuedAt| <= 300001       0x140222E73   else -> "Your system clock is too far off"
  expires_at > now()               0x140222F1E   else -> "You have no time left. Top up on the site."
  token present                    0x140222F20   else -> "Madium did not return a session"
```

and the cached path (verdict from `/keys/auth/secure`):

```
  Ed25519 verify                   0x14021F52E   else -> "forged_signature"
  nonce == local nonce             0x14021F59F   else -> "nonce_mismatch"
  hwid == local hwid               0x14021F600   else -> "hwid_mismatch"
  |now - issuedAt| <= 300000       0x14021F656   else -> "stale_verdict"
  status == "LICENSE_VALID"        0x14021F718   else -> "reason" / "license_invalid"
  expires_at                       0x14021F749
```

**The branch polarity was measured, not assumed.** The string-compare helper at
`0x1400D0BD5` returns **0 on equal and 1 on differ**, confirmed independently at three
sites: `alg` against `"Ed25519"` (equal -> proceed), `hwid` against the local id (equal ->
proceed) and `status` against `"LICENSE_VALID"` (equal -> accept branch). Every patch
direction below follows from that measurement.

### The trust anchor

The server's Ed25519 **verifying** key is pinned in the image:

```
  file 0xB2FF16   VA 0x140B30D16   32 bytes
  23572ca500262e26595b8667682fcaecb2a33264e1b242c11684333f46080125
```

It is loaded at `0x14021FCE8` and `0x14021FCF2` and used to check a 64-byte signature
(`cmp qword ptr [rsp + 0x7B0], 0x40` at `0x14021FC42`). The point decodes as a valid
Ed25519 curve point. **No private key ships in the client**, so a verdict cannot be forged
without moving the anchor - which is exactly what patch 7 does.

### The canonical signed message

The signature does not cover the raw response body. It covers a canonical JSON form of the
signed fields, and the form was recovered by brute-forcing candidate canonicalisations
against a **genuine server-signed verdict** until one verified under the pinned key:

```
{"hwid":"...","issuedAt":1792643640770,"nonce":"...","reason":"bad_session",
 "status":"LICENSE_INVALID","timestamp":"2026-10-22T04:34:00.770Z"}
```

The rule: **the signed object, minus `alg` and `signature`, serialised with keys sorted
alphabetically and compact separators (`","`, `":"`).** The mock endpoint reproduces it
exactly, which is why its verdicts verify under a replaced anchor.

### The response shape

The sign-in response is nested, and the nesting is load-bearing. From the disassembly:

```
0x1402228BD  map_get("error")        ; the key MUST exist
0x1402228D3  byte[0] == 1            ; must be a bool (serde_json tag 1)
0x1402228D8  byte[1] == 0            ; must be FALSE, else "Sign-in failed"
0x140222969  map_get("message")      ; the key MUST exist
0x14022298A  byte[0] == 5            ; must be an object (serde_json tag 5)
0x1402229CE  map_get("alg")          ; session fields live INSIDE "message"
```

`alg`, `signature`, `hwid`, `issuedAt`, `expiresAt` and `token` are all read out of the
`message` **object**, not out of the root. A flat response is rejected with
*"Madium sent an invalid response"* - which is the first symptom of a wrong shape, and the
reason the endpoint ships a shape-corrected responder rather than a plausible-looking one.

---

## 5. The eight patches

### Patch 1 - expiry gate

```
file 0x22231E   VA 0x140222F1E   .text   2 bytes
  7E 70   jle 0x140222F90    ->  90 90
```

`cmp rbp, rax` compares `expires_at` against `now()`; `jle` leaves the verdict when the
licence has run out. NOPing the branch leaves the verdict accepted on that comparison
alone.

### Patch 2 - device binding

```
file 0x222207   VA 0x140222E07   .text   2 bytes
  74 2E   je 0x140222E37     ->  EB 2E
```

The compare helper returns 0 on equal, so `je` is the *equal -> continue* edge. Making it
unconditional keeps the verdict flowing whatever the device id says.

### Patch 3 - clock skew window

```
file 0x22227A   VA 0x140222E7A   .text   2 bytes
  72 71   jb 0x140222EED     ->  EB 71
```

`cmp r14, 0x493E1` against `|now - issuedAt|`; `jb` is the *within window -> continue*
edge. Making it unconditional drops the window.

### Patch 4 - status gate

```
file 0x21EB1F   VA 0x14021F71F   .text   2 bytes
  74 28   je 0x14021F749     ->  EB 28
```

Same shape as patch 2, on the `status` string: `je` is *equal -> accept*. Unconditional
means the accept branch is always taken.

### Patch 5 - signature result, verdict path

```
file 0x21E945   VA 0x14021F545   .text   2 bytes
  74 2B   je 0x14021F572     ->  90 90
```

`test al, al` after the Ed25519 call; `je` leaves the flow when the verification failed
(*"forged_signature"*). NOPing it keeps the verdict flowing.

### Patch 6 - signature result, sign-in path

```
file 0x2221D1   VA 0x140222DD1   .text   2 bytes
  74 4D   je 0x140222E20     ->  90 90
```

The same edge on the sign-in path (*"Madium's session signature did not verify"*).

### Patch 7 - trust anchor

```
file 0xB2FF16   VA 0x140B30D16   .rdata   32 bytes
  23572ca500262e26595b8667682fcaecb2a33264e1b242c11684333f46080125
  -> the public key of the locally generated keypair
```

Replacing the pinned verifying key moves the trust decision onto a keypair whose private
half never leaves disk. It is what lets the local endpoint's verdicts be accepted by the
client's own verifier, with no change to the verifier itself.

### Patch 8 - auth host

```
file 0xB2FB94   VA 0x140B30994   .rdata   26 bytes
  https://auth.getmadium.xyz  ->  http://127.0.0.1:8080
file 0xB2FBB8   VA 0x140B309B0   .rdata    8 bytes
  length 26                   ->  length 21
```

The host is one fat pointer - a pointer to the string plus its length - and **both** auth
endpoints read it (`0x14021EC43` for `/keys/auth/secure`, `0x14022262D` for
`/account/auth`), so one edit moves both. The scheme becomes `http`, which means the
rustls `WebPkiServerVerifier` is never reached and no certificate is involved at all.

### Writing it back

Writing the eight original signatures over a patched file reproduces the pristine SHA-256
byte for byte - the patch provably touches nothing else.

---

## 6. Verification

`tools\shape_check.py` proves the response shape against the live service and against the
addresses the client reads:

```
[1] the real server's error envelope shape
  status 401
  body   {"error":true,"message":"Wrong username or password"}
  [PASS] real server sends an 'error' key
  [PASS] real server sends a 'message' key
  [PASS] real 'error' is a bool
[4] sign it with a keypair and verify against the patched anchor
  [PASS] signature verifies over canonical(message)
  [PASS] anchor rejects the forged signature
ALL CHECKS PASSED
```

`MadiumPatch.ps1 -List` reports the state of every site on the live binary:

```
SITE     VA                 FILE       BYTES     STATE     DESCRIPTION
expiry   0x000140222F1E 0x0022231E   90 90     patched   expires_at <= now() no longer aborts the verdict
hwid     0x000140222E07 0x00222207   EB 2E     patched   device binding always continues past the hwid check
clock    0x000140222E7A 0x0022227A   EB 71     patched   issuedAt skew window is always accepted
status   0x00014021F71F 0x0021EB1F   EB 28     patched   status string is always taken as the accept branch
sig1     0x00014021F545 0x0021E945   90 90     patched   Ed25519 result ignored on the verdict path
sig2     0x000140222DD1 0x002221D1   90 90     patched   Ed25519 result ignored on the sign-in path
host     -                  0xB2FB94   http://127.0.0.1:8080 redirected auth host
hostlen  -                  0xB2FBB8   21                    host string length
pubkey   -                  0xB2FF16   747acf12fb66a02b1... -      pinned Ed25519 verifying key
```

The endpoint announces the moment the client moves on:

```
[mock] sign-in a accepted
[mock]   root keys: ['error', 'message']
[mock]   message keys: ['alg', 'expiresAt', 'hwid', 'issuedAt', 'key', 'nonce',
                         'reason', 'signature', 'status', 'timestamp', 'token']
[mock] SUCCESS SIGNAL: client requested /keys/auth/secure
```

`tools\install_test.py` runs the whole thing end to end against a scratch copy and checks
every component of the bypass on disk, not just the exit code:

```
=== C. every site patched on disk ===
  [PASS] site expiry patched
  [PASS] site hwid patched
  [PASS] site clock patched
  [PASS] site status patched
  [PASS] site sig1 patched
  [PASS] site sig2 patched
  [PASS] auth host redirected  -> http://127.0.0.1:8791
  [PASS] host length field updated  -> 21
  [PASS] pinned key replaced
=== D. backup + state ===
  [PASS] backup holds the pristine bytes  -> ad1daac9f09763fb6632df5f92c76073e3c02cb4766917277e6469f9fb9f0a7a
  [PASS] keypair written
  [PASS] no keypair leaked into the repo
=== E. endpoint answers ===
  [PASS] endpoint is serving
=== F. re-run the installer (re-patch over a patched binary) ===
  [PASS] second install exits 0
=== G. uninstall ===
  [PASS] uninstall exits 0
  [PASS] pristine binary restored
  [PASS] keypair removed
  [PASS] endpoint stopped
ALL CHECKS PASSED
```

---

## 7. Exit codes

| code | meaning |
|---|---|
| 0 | patched, already in the requested state, or fast-path confirmed |
| 1 | access denied (not elevated) |
| 2 | target missing or not a PE image |
| 3 | target locked |
| 4 | dark: signature missing or ambiguous on this build - **nothing written** |
| 5 | verify/swap failure - **file left on disk untouched** |

---

## 8. Limits

- **One build.** The patcher refuses a binary whose SHA-256 is not the analysed one, unless
  every byte site is in a state it recognises - pristine or already patched - in which case
  the build is accepted and the patch is applied to what is missing. There is no matcher
  here - the sites are byte-exact, so a re-analysis is needed after an update.
- **The endpoint must be running.** The client is pointed at `127.0.0.1:8080`. Kill the
  process and the client cannot authenticate.
- **The patched binary only trusts this endpoint.** Because patch 7 replaces the pinned key,
  a verdict signed by the real vendor is rejected by the patched client. Restore with
  `uninstall.cmd` before contacting the real service.
- **The 402 stays 402.** Against the real service, an expired account is refused at
  `POST /account/auth` before any verdict is signed. No client-side patch changes that; the
  only way for the client to reach the workbench is to answer the request itself, which is
  what the local endpoint does.
- **The frontend was not modified.** The gate is enforced in Rust. The `LicenseStatus`
  struct the WebView2 frontend renders comes from the patched Rust code, so the frontend
  needed no change - but no attempt was made to extract or patch the embedded Tauri asset
  bundle.
- **The payload is untouched.** `Madium.dll` is fetched from the public CDN and its
  SHA-256 is still checked against the manifest by the client.

---

## 9. The analysis tooling

```
tools\madium_mockauth.py   the local auth endpoint - speaks both endpoints, signs with Ed25519
tools\capture_real.py      capture the real service's raw reply, for any endpoint and credentials
tools\shape_check.py       prove the response shape against the live service and the client
tools\madium_unlock.cpp    standalone C++ patcher (same sites, no PowerShell dependency)
tools\madium_unlock.exe    the compiled patcher, so no C++ toolchain is needed
tools\install_test.py      end-to-end test of the installer against a scratch copy
tools\rebuild_pristine.py  reconstruct the pristine binary from a patched one
```

`capture_real.py` talks to the real service directly, over TLS, exactly like the client -
no patching involved. It exists so the protocol can be re-checked without trusting a
remembered transcript.

`install_test.py` runs the real installer against a copy of the binary in a temp directory
and then checks all of it: that the installer exits 0, that all eight sites are patched on
disk, that the backup holds the pristine bytes, that the keypair was written and did not
leak into the repo, that the endpoint answers, that a second install over an already-patched
binary still succeeds, that re-patching onto a different port rewrites the host, and that
the uninstall restores the pristine binary and stops the endpoint.

`rebuild_pristine.py` writes the original bytes back over a patched binary. The patch
touches a known, bounded set of bytes, so the result must reproduce the pristine SHA-256
exactly - which is the proof that the patch is the only thing that differs:

```
> python tools\rebuild_pristine.py Madium.exe pristine.exe
rebuilt  sha256 ad1daac9f09763fb6632df5f92c76073e3c02cb4766917277e6469f9fb9f0a7a
written pristine.exe - matches the pristine build exactly
```

---

The client pins the server's Ed25519 verifying key inside its own binary, checks a
signature over a canonical JSON form of the verdict fields, and refuses a verdict whose
`error` flag is set. This folder replaces the pinned key with one you control, points the
auth host at loopback, and answers both endpoints with verdicts the client accepts.
