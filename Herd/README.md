# Herd — License Unlock (ASAR Baked Shim)

Local, restart-proof unlock for **Laravel Herd** on Windows. Herd ships its main
process as V8 cached-data bytecode inside `resources\app.asar`, so there is no IL
to rewrite and no symbol to rename. The patch appends a small shim to the
archive's `out/main/index.js` entry instead: Herd runs it on every boot, and it
shadows the Pro accessors on `LicenseManager.prototype` before the window ever
asks.

Nothing here is a launcher and nothing lives in memory. The archive itself
carries the patch, so Herd starts licensed from the Start Menu, from the tray,
from `Herd.exe` directly — no `--inspect`, no environment variable, no second
process running alongside it.

Everything operates on your own installation, on disk, with no network calls and
no license server interaction. **7,745 bytes of shim added to a 156,017,102-byte
archive. The other 19,516 files keep their exact offset and their exact bytes.**

---

## Table of contents

1. [Current version / verified build](#1-current-version--verified-build)
2. [TL;DR — install](#2-tldr--install)
3. [What it does / what it does NOT do](#3-what-it-does--what-it-does-not-do)
4. [How Herd's licensing actually works](#4-how-herds-licensing-actually-works)
5. [Why there is nothing to decompile](#5-why-there-is-nothing-to-decompile)
6. [Finding `LicenseManager` without a name](#6-finding-licensemanager-without-a-name)
7. [The shim — shadowing the prototype](#7-the-shim--shadowing-the-prototype)
8. [The archive surgery](#8-the-archive-surgery)
9. [The header field that fails silently](#9-the-header-field-that-fails-silently)
10. [Surviving updates](#10-surviving-updates)
11. [Files](#11-files)
12. [Verification / evidence](#12-verification--evidence)
13. [Rollback](#13-rollback)
14. [Regenerating the analysis](#14-regenerating-the-analysis)
15. [Failure modes](#15-failure-modes)
16. [Limits](#16-limits)

---

## 1. Current version / verified build

| | |
|---|---|
| Product | Laravel Herd, `Herd.exe` FileVersion **2.0.1** |
| Install dir | `C:\Program Files\Herd` |
| `Herd.exe` | 246,081,800 bytes |
| `resources\app.asar` | 156,017,102 bytes |
| Archive contents | 23,707 tree nodes — **19,517 files**, 4,190 directories, deepest nesting 11 |
| Unpacked | 210 files live in `resources\app.asar.unpacked` and are *not* touched |
| Integrity digests | all 19,517 file entries carry one |
| Entry point | `package.json` → `./out/main/index.js` |
| `out/main/index.js` | 72-byte loader |
| `out/main/index.jsc` | 2,409,824 bytes, V8 cached data (magic `cf06dec0e5d6f5d2`) |
| Runtime | Electron 44.x, Node (Herd's own `RuntimeAsNode` fuse is enabled) |

Hashes for the exact build this was developed against:

| | SHA-256 |
|---|---|
| `app.asar` before | `a058773356be61dd36f1597bc9fdb4dcc08b68d72cd74be9563ce8f9afa68cac` |
| `app.asar` after | `9c267b2bc204ccbe756c01501c5227f28a3e23447fcbe4ca2dbed7188d0d575f` |
| `out/main/index.jsc` | `7b59d7f1584be80f4be6f22c3d6c99ce8b0356282a8effab6825ed5bf2d2a11b` |

`out/main/index.js` is 72 bytes and looks like this:

```js
"use strict";
require("./bytecode-loader.cjs");
require("./index.jsc");
```

The whole patch is that file plus 7,798 bytes appended to it.

---

## 2. TL;DR — install

```cmd
git clone https://github.com/0xLLVEL/reapower.git
cd reapower\Herd
install.cmd
```

`install.cmd` requests UAC, then `Install-HerdPatch.ps1`:

1. copies `HerdPatch.ps1` + `HerdShim.js` to `C:\ProgramData\HerdPatch`
2. takes a pristine copy of `app.asar` into `C:\ProgramData\HerdPatch\backup\app.asar.orig`
3. closes Herd if it is running, bakes the shim in, restarts it
4. registers the scheduled task **Herd License Patch** (at logon + every 10 min,
   `RunLevel Highest`) so the bake comes back by itself after an update

```powershell
# patch state
powershell -ExecutionPolicy Bypass -File .\HerdPatch.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File .\HerdPatch.ps1 -Force

# undo
uninstall.cmd
```

---

## 3. What it does / what it does NOT do

**Does**

- Makes the main process report a valid, lifetime Pro license through the same
  IPC channels the renderer already uses.
- Survives a full process kill, a reboot, and an in-app auto-update.
- Leaves 19,516 of 19,517 files byte-identical, at identical offsets.
- Undoes cleanly from the backup copy of the archive.

**Does NOT**

- Touch `C:\Users\<you>\.config\herd\**` — the tool never writes a config file.
- Touch the PHP side, the nginx/caddy configs, the certificates, or any service.
- Patch `Herd.exe`, use DLL injection, a proxy, a hosts entry, or a fake server.
- Talk to anything over the network.
- Persist anything in memory only — that is the other path, see
  [section 14](#14-regenerating-the-analysis).

---

## 4. How Herd's licensing actually works

Dumping `Object.getPrototypeOf(LicenseManager.shared)` from a live process gives
the complete surface. Every name below is real, read straight off the prototype:

```
getters
  hasValidLicense        licenseKey            isLifetimeLicense
  licenseExpiresSoon     licenseExpiresIn      needsRenewalCopy
  info                   deviceName            deviceId
  canReceiveTrialDumps   remainingTrialDumps
  salePromoText          saleCheckoutUrl       siteInfoSalePayload

methods
  validate/1             requestValidation/1   activate/2
  refreshLicenseAfterCheckout/0                refreshIfReturningFromCheckout/0
  startValidating/0      stopValidating/0      setRefreshStatus/1
  startPinging/0         stopPinging/0         schedulePingRetry/0   ping/0
  onLicenseChanged/1     publishLicenseState/0 openSaleCheckout/0
  incrementDumps/0       lifetimeCelebrated/0  deactivate/1
  markLicenseAsDeactivated/0                   markLicenseAsActivated/1

instance fields
  maxAllowedDumpsDuringTrial   refreshStatus   lifetimeCelebrationPending
  saleCheckoutReturn           pingRetryArmed

statics
  shared   _shared
```

The shape is a plain cached singleton. The renderer never sees the object — it
asks the main process over IPC (`licensing.has-valid-license`,
`licensing.license-key`, `licensing.info`, …) and the handlers answer from
`LicenseManager.shared`.

Three things follow, and they are the whole design:

- `hasValidLicense` is a **getter on the prototype**. Shadowing it on the
  prototype changes the answer for the singleton and for every future one.
- The state is **cached**. `publishLicenseState()` broadcasts whatever the getters
  now return, so the renderer updates without a restart.
- The network paths (`validate`, `ping`, `refreshIfReturningFromCheckout`) can
  only ever *flip the state back*. Replace them with no-ops and there is nothing
  left that can revoke it.

---

## 5. Why there is nothing to decompile

`out/main/index.js` is a 72-byte loader. The real bundle is `out/main/index.jsc`,
2,409,824 bytes starting with `cf 06 de c0 e5 d6 f5 d2` — a V8 cached-data
header. It is bytecode for one exact V8 build, and it is not a supported input to
any public decompiler: `GetOwnPropertyNames` on the loaded module closure is the
closest thing to a symbol table you are going to get.

That is why this repository patches behaviour instead of bytes. There is no
IL-level `IsLicensed` here to flip — the equivalent is a class that only exists
as a closure binding, and a getter that only exists at runtime.

The names in [section 4](#4-how-herds-licensing-actually-works) were therefore
recovered at runtime, from a live process, not from a static file.

---

## 6. Finding `LicenseManager` without a name

There is no global to reach for. `LicenseManager` is a binding in the bundle
module's scope, and the only durable handle on that scope is a closure: the
`licensing.*` IPC handlers are created inside the bundle and close over it.

The in-process inspector exposes exactly what is needed. For any function object,
`Runtime.getProperties` returns an `internalProperties` list containing
`[[Scopes]]` — the runtime's own closure list, including the `Closure` record
holding the module scope. So:

```
Runtime.evaluate       require('electron').ipcMain._invokeHandlers.get('licensing.has-valid-license')
Runtime.getProperties  -> internalProperties [[Scopes]]
Runtime.getProperties  -> scope "0"  == the bundle module scope
Runtime.getProperties  -> binding "LicenseManager"
Runtime.callFunctionOn -> this.shared
```

Four `getProperties` calls and the singleton is in hand. It works for any class
in any Electron bundle as long as something reachable closes over it.

Reaching the inspector **from inside the process** needs no port and no
`--inspect` flag: the main process can `require('inspector')` and
`new inspector.Session()` on itself. That is what makes the baked shim possible,
and it is why `NODE_OPTIONS=--require` is a dead end here — it was tried, it was
ignored regardless of the `EnableNodeOptionsEnvironmentVariable` fuse, and it
would have needed a second file next to the exe anyway.

---

## 7. The shim — shadowing the prototype

`HerdShim.js` runs at the top of the main process, waits for `ipcMain` to have
the licensing handler registered (250 ms poll, 120 s ceiling, normally first
attempt), walks the closures once, and then:

- `Object.defineProperty` on the prototype for fourteen getters:
  `hasValidLicense`, `licenseKey`, `isLifetimeLicense`, `licenseExpiresSoon`,
  `licenseExpiresIn`, `needsRenewalCopy`, `info`, `canReceiveTrialDumps`,
  `remainingTrialDumps`, `salePromoText`, `saleCheckoutUrl`, `siteInfoSalePayload`
- `Object.defineProperty` with a resolving no-op for the twelve network/refresh
  entry points — `validate`, `requestValidation`, `refreshLicenseAfterCheckout`,
  `refreshIfReturningFromCheckout`, `startValidating`, `stopValidating`,
  `startPinging`, `stopPinging`, `schedulePingRetry`, `ping`, `setRefreshStatus`,
  `activate` — plus `incrementDumps` and `markLicenseAsDeactivated`, the one
  method that could actually clear a license
- `deactivate` resolves `false` instead of performing a deactivation
- the instance fields the class reads back (`refreshStatus`,
  `lifetimeCelebrationPending`, `pingRetryArmed`) are reset

Everything else is left alone. The shim is written in ES5, has no dependencies,
and logs three lines to `%APPDATA%\Herd\herd-pro.log`:

```
[2026-10-17T11:12:49.794Z] shadow installed on LicenseManager.prototype
[2026-10-17T11:12:49.797Z] hasValidLicense => true
[2026-10-17T11:12:49.799Z] done after 1 attempt(s)
```

Shadowing the prototype rather than the instance is deliberate: the class is a
cached singleton reached through `LicenseManager.shared`, and anything that
re-reads the class later gets the same answer.

---

## 8. The archive surgery

An ASAR is a header pickle followed by one contiguous data region:

```
[ u32 ] 4                          size-pickle payload length
[ u32 ] headerPickleSize           length of the header pickle buffer
[ u32 ] headerPickleSize - 4       header-pickle payload length
[ u32 ] jsonLen                    header JSON string length
[ .. ] header JSON, zero-padded to a 4-byte boundary
[ .. ] data region — every file, concatenated
```

A file entry's `offset` is relative to the **start of the data region**, not to
the file. That single fact is what makes this patch cheap:

- the header changes size, so the data region slides by `delta`
- every existing `offset` is unaffected, because all of them are relative
- exactly one entry needs a new offset, and its value is simply `oldDataSize`
  — the file is appended at the end

So the engine rewrites the header, streams the 150,895,202-byte data region
across verbatim, appends 7,870 bytes, and stops. No re-packing, no re-hashing, no
per-file work, and 19,516 of 19,517 entries are provably untouched.

The engine refuses to write unless it can prove that first. It flattens both the
original and the round-tripped header into `path::property -> value`, diffs them,
and aborts if anything outside the target entry moved. A 23,707-node JSON
round-trip that silently mangles one sibling is not something you want to
discover as a white window.

The shim is appended **after** the loader, not written over it:

```
"use strict";
require("./bytecode-loader.cjs");
require("./index.jsc");
/* ---- herd-pro ---- */
(function () { ... })(function () {})();
/* ---- /herd-pro ---- */
```

`electron-updater` replaces `resources\app.asar` wholesale, so those two marker
comments are also the state: the poll reads the last 8 KiB of the archive and
looks for `/* ---- /herd-pro ---- */`. Found → nothing to do, exit in under a
second. Not found → the archive was replaced, re-bake from the pristine backup.

No manifest, no lock file, no state directory to get out of sync with reality.

---

## 9. The header field that fails silently

The first version of this patch worked in a sandbox and produced a Herd that
refused to start: no window, no error dialog, no shim log, nothing.

```
[23300:ERROR:electron\shell\common\asar\archive.cc:246] Failed to parse header from \\?\...\app.asar
```

The cause was one field. The header pickle is a `Pickle` whose payload length
lives at offset 8 of the file, and it must be `headerPickleSize - 4`:

```
[ u32 ] 4                      ok
[ u32 ] headerPickleSize       ok
[ u32 ] headerPickleSize - 4   <-- this one
[ u32 ] jsonLen                ok
```

Writing `jsonBytes.length` there instead produces an archive that looks
structurally fine, is the right length, has a valid JSON tree, and still makes
Electron drop the entire archive before a line of JS runs. The failure is
completely silent from the outside — the process just exits.

It was isolated by patching 4 bytes of a working archive to the wrong value and
watching it reproduce exactly, then reverted. `bake_reference.cjs` and
`HerdPatch.ps1` both carry the comment; `tools/compare_asar.ps1` will catch it
after the fact.

---

## 10. Surviving updates

`electron-updater` downloads a new `app.asar` and replaces the file. There is no
patch to carry forward and no byte offset to reapply — the new archive is just a
new vendor build, and the whole bake has to happen again.

That is what the scheduled task is for. Every ten minutes:

1. read the last 8 KiB of `app.asar`
2. marker present → exit, `~0.9 s`
3. marker absent → refresh the pristine backup from the new archive, re-bake,
   restart Herd if it had been running

The backup is refreshed **before** the bake, from the archive as it exists at
that moment, so it always holds the newest vendor build rather than the oldest.

A poll that finds nothing costs one 8 KiB read and never closes Herd — the fast
path runs before any process handling.

---

## 11. Files

```
Herd/
  README.md                 this file
  HerdPatch.ps1             engine — bakes the shim into app.asar
  HerdShim.js               the payload, baked into out/main/index.js
  Install-HerdPatch.ps1     installer / uninstaller + scheduled task
  install.cmd               self-elevating wrapper
  uninstall.cmd             self-elevating wrapper, -Uninstall
  tools/
    compare_asar.ps1        prove a rewrite changed one entry and nothing else
    scan_fuses.ps1          read the Electron fuse wire out of an exe
    patch_cdp.cjs           runtime attach: walk the closures, patch or --check
    bake_reference.cjs      the same asar rewrite in node, as a second opinion
```

State, created by the installer at `C:\ProgramData\HerdPatch`:

```
HerdPatch.ps1               copy of the engine the task runs
HerdShim.js                 copy of the payload
backup\app.asar.orig        pristine archive, per vendor build
```

The engine will also accept a pristine `app.asar.orig` sitting next to the
archive, so a manual backup works too.

---

## 12. Verification / evidence

### The rewrite touched one entry

`tools/compare_asar.ps1` flattens both headers and diffs every node, then
compares the two data regions byte for byte:

```
ASAR compare
  A (original) = A058773356BE61DD36F1597BC9FDB4DCC08B68D72CD74BE9563CE8F9AFA68CAC
  B (patched)  = 9C267B2BC204CCBE756C01501C5227F28A3E23447FCBE4CA2DBED7188D0D575F
  size A       =     156,017,102 bytes
  size B       =     156,024,768 bytes
  entries      =          23,707  /  23,707
  header diffs = 0 outside out/main/index.js

  inside out/main/index.js:
      out/main/index.js::size : '72' -> '7870'
      out/main/index.js::integrity::algorithm : 'SHA256' -> '<absent>'
      out/main/index.js::integrity::hash : '9a0e2c…5046' -> '<absent>'
      out/main/index.js::integrity::blockSize : '4194304' -> '<absent>'
      out/main/index.js::integrity::blocks : '9a0e2c…5046' -> '<absent>'
      out/main/index.js::offset : '4866613' -> '150895202'

  data region  : 150,895,202 bytes compared byte for byte - identical
  appended     : 7,870 bytes at the end of B
```

Six changed fields, all inside the one entry, and 150 MB of file content that
does not move. The integrity digest is dropped because the content it describes
is gone; Electron's `EnableEmbeddedAsarIntegrityValidation` fuse is what would
have enforced it, and it is disabled in this build.

### The archive Electron actually accepts

`Herd.exe` was launched with no arguments, from the patched archive, and the shim
reported in on its own.

### The license, read back out of the live process

`tools/patch_cdp.cjs --check` attaches to a running Herd and reports what the
class believes. It installs nothing — so the values below come from the baked
shim, not from the checker:

```
LicenseManager.shared:
{
 "hasValidLicense": true,
 "licenseKey": "HERD-PRO-4080-0000-1111-2222-3333-4444-5555",
 "isLifetimeLicense": true,
 "deviceName": "DESKTOP-BB99JUB",
 "licenseExpiresSoon": false,
 "licenseExpiresIn": -1,
 "needsRenewalCopy": false,
 "remainingTrialDumps": 9007199254740991,
 "info": {
  "hasValidLicense": true,
  "hasLicenseExpired": false,
  "licenseIsLifetime": true,
  "licenseExpiresIn": -1
 }
}
PASS: LicenseManager reports a valid license
```

### Electron fuses

`tools/scan_fuses.ps1 -Exe 'C:\Program Files\Herd\Herd.exe'`:

```
  wire offset    : 199176568
  schema version : 1
  fuse count     : 9

  0  RunAsNode                                  ENABLED
  1  EnableCookieEncryption                     disabled
  2  EnableNodeOptionsEnvironmentVariable       ENABLED
  3  EnableNodeCliInspectArguments              ENABLED
  4  EnableEmbeddedAsarIntegrityValidation      disabled
  5  OnlyLoadAppFromAsar                        disabled
  6  LoadBrowserProcessSpecificV8Snapshot       disabled
  7  GrantFileProtocolExtraPrivileges           ENABLED
  8  fuse#8                                     ENABLED
```

Two of these matter: `EnableEmbeddedAsarIntegrityValidation` disabled is why a
rebuilt `app.asar` is accepted at all, and `OnlyLoadAppFromAsar` disabled is why
the process can still start if the archive is damaged. `EnableNodeCliInspectArguments`
is what makes the `--inspect` route usable for analysis.

### Restarts

Hard-killed with `Stop-Process -Force` and relaunched repeatedly. Every boot logs
`shadow installed on LicenseManager.prototype` / `hasValidLicense => true`. The
shim is in the archive; there is no state to lose.

---

## 13. Rollback

```cmd
uninstall.cmd
```

That removes the scheduled task and copies `backup\app.asar.orig` back over
`resources\app.asar`. Nothing else was ever modified, so nothing else needs
undoing — verify with `tools/compare_asar.ps1` against another copy of the
pristine archive if you want the hash back.

Note the ordering: removing the task first matters. If you restore the archive
while the poll is still registered, the next tick patches it again.

---

## 14. Regenerating the analysis

Herd's licensing is not visible statically. To reproduce the findings above you
need a live process:

```powershell
# 1. what is in the archive
node tools\bake_reference.cjs --asar "$env:ProgramFiles\Herd\resources\app.asar" `
     --src <loader.js> --append HerdShim.js --out .\probe.asar

# 2. start Herd with an inspector and walk it
& "$env:ProgramFiles\Herd\Herd.exe" --inspect=9333
node tools\patch_cdp.cjs --check           # report only, install nothing
node tools\patch_cdp.cjs                   # install the shadow in-memory

# 3. confirm the archive rewrite is honest
powershell -ExecutionPolicy Bypass -File tools\compare_asar.ps1 `
     -Original .\app.asar.orig -Patched "$env:ProgramFiles\Herd\resources\app.asar"

# 4. fuses
powershell -ExecutionPolicy Bypass -File tools\scan_fuses.ps1 `
     -Exe "$env:ProgramFiles\Herd\Herd.exe"
```

`patch_cdp.cjs` is the runtime path: the shadow lives in process memory and is
gone when Herd exits. It is how the closure walk was found and confirmed, and it
needs node — or `Herd.exe` itself, since `RunAsNode` is enabled:

```cmd
set ELECTRON_RUN_AS_NODE=1
"C:\Program Files\Herd\Herd.exe" tools\patch_cdp.cjs --port 9333
```

---

## 15. Failure modes

| Symptom | Cause |
|---|---|
| Herd starts, no window, no shim log, `archive.cc:246 Failed to parse header` in stderr | The header-pickle payload length at file offset 8 is wrong. See [section 9](#9-the-header-field-that-fails-silently). |
| Herd starts, shim log says `install failed: LicenseManager not in bundle scope` | The bundle's scope layout changed in this build. Re-run the closure walk from [section 6](#6-finding-licensemanager-without-a-name) and update the `scope "0"` / binding names. |
| Shim log never appears at all | The baked entry did not run: the archive was replaced by an update and the poll has not fired, or the wrong archive is loaded. Check the tail marker. |
| `PASS` in the shim log but the UI still shows no Pro | The renderer asked before the shadow landed. The poll is 250 ms and normally first-attempt; if it persists, `publishLicenseState` is not being honoured in this build. |
| `refusing to write a header that does not round-trip` | The JSON round-trip mangled a sibling entry. Nothing was written. Capture the diff the engine printed and treat it as a bug. |
| `backup … is itself patched` | The backup was taken after a bake. Restore or reinstall Herd, then reinstall the patch. |

---

## 16. Limits

- **Windows only.** The engine is PowerShell 5.1 and `.NET` `FileStream` work;
  the paths are the Windows ones. The analysis in sections 4–7 is
  platform-independent, only the installer is not.
- **Version-specific.** The closure walk assumes the licensing IPC handler is
  registered before the window opens and that `LicenseManager` stays a binding in
  the bundle's top-level scope. A restructure there needs a new walk.
- **PowerShell 5.1 JSON is too slow, which is why the engine does not use it.**
  `ConvertFrom-Json` / `ConvertTo-Json` need ~70 s on a 5.1 MB header;
  `JavaScriptSerializer` does the same round-trip in about a second. Use the
  .NET serializer if you extend this.
- **It is a patch on the client.** It changes what this process believes about
  itself. It does not create an account, a key, or anything valid server-side,
  and it is not meant to.
