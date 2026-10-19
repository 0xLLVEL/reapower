# Lunar Client — Integrity Gate Unlock (makes `app.asar` editable)

Local patcher for the **Lunar Client launcher** (Moonsworth LLC, `lunarclient` **3.7.25-ow**,
Electron **42.7.1**). It removes the launcher's self-integrity gate: the Electron
*asar-integrity* fuse is blown off and the Overwolf `owepm` validator stops being able to
block startup, so `resources\app.asar` can be edited without the launcher refusing to run.

Everything here operates on your own installation, on disk, with no network calls.
It is an analysis of a shipped native binary and a byte-level patch of it:
**8 bytes of 235,252,216 actually differ**, written across three logical sites —
one Electron fuse byte and seven JavaScript flag bytes inside the embedded validator.

---

## Table of contents

1. [Target / verified build](#1-target--verified-build)
2. [TL;DR — usage](#2-tldr--usage)
3. [What it does / what it does NOT do](#3-what-it-does--what-it-does-not-do)
4. [How Lunar's integrity gate actually works](#4-how-lunars-integrity-gate-actually-works)
5. [The eight bytes](#5-the-eight-bytes)
6. [Verification](#6-verification)
7. [Limits](#7-limits)
8. [Stage 2 — the Minecraft ownership gate (not shipped yet)](#8-stage-2--the-minecraft-ownership-gate-not-shipped-yet)

---

## 1. Target / verified build

| field | value |
|---|---|
| target | `%LOCALAPPDATA%\Programs\Lunar Client\Lunar Client.exe` |
| product | `lunarclient` 3.7.25-ow — Moonsworth LLC |
| shell | Electron 42.7.1, x64 PE, 235,252,216 bytes |
| code signature | Authenticode **untouched** (the patch never rewrites signed sections' semantics, it flips data bytes) |
| sha256 pristine | `C1D3F36DBA310629AEDEC239B6C55A2F1CFE21E6930DFF2EE0440C169718628E` |
| sha256 patched  | `CC94512FA4AC83D88A1EEA94A24D8D066D037F411B96CF7D23CB3ECA3A3C36D7` |
| bytes written | **8**, across 3 logical sites |
| companion | `integrity.dll` 13,840 B (Overwolf public-key carrier), `owutility.dll` 3,107,984 B (Overwolf Electron Utility 0.0.0.56), `resources\app.asar` 25,797,518 B — all untouched by this stage |

A different Lunar build gets different offsets. The matcher fails hard instead of guessing:
see [§5](#5-the-eight-bytes).

---

## 2. TL;DR — usage

```
status.cmd     report pristine / patched / unknown + the 8 site states
patch-now.cmd  back up the pristine exe, write the 8 bytes, verify by re-reading
revert.cmd     restore the pristine exe from the backup (sha-checked before restore)
```

Close the launcher first — the script refuses to touch a running instance.

---

## 3. What it does / what it does NOT do

**Does:**

* Blows Electron's `enableEmbeddedAsarIntegrityValidation` fuse **off**, so Electron stops
  re-hashing `app.asar` at load time.
* Neutralises the Overwolf `owepm` validator so it can no longer return `blocked: true` —
  which was the thing that aborted startup with
  `invalid verification (browser: …)`.
* Leaves a byte-identical pristine backup and restores it on `-Mode Revert`.

**Does NOT:**

* Does **not** touch `app.asar`, `main.js`, `integrity.dll`, `owutility.dll`, the Authenticode
  signature, or any registry/file outside the exe and its backup.
* Does **not** bypass the Minecraft account requirement — that check is server-side
  (Mojang) and lives in `main.js`, and it needs stage 2
  ([§8](#8-stage-2--the-minecraft-ownership-gate-not-shipped-yet)).
* Does **not** grant multiplayer on online-mode servers, Lunar's own network features,
  or anything else a real Microsoft/Mojang session provides.

---

## 4. How Lunar's integrity gate actually works

Two independent mechanisms both have to be defeated before `app.asar` is writable.

**a) Electron's asar-integrity fuse.** The fuse wire sits in the exe right after the
32-byte `@electron/fuses` marker `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`:

```
offset +32 : 0x01          fuse wire version
offset +33 : 0x09          fuse count (9)
offset +34 : "101111011"   the nine fuse values, ASCII '1'/'0'
             ^^
             idx 4 = enableEmbeddedAsarIntegrityValidation = '1' (on)
```

With that fuse on, Electron validates the asar contents before serving a single file from
it — so any edit to the archive kills the app regardless of application code.

**b) The Overwolf validator.** `ow-electron-package-manager`'s
`OverwolfBrowserPackagesValidationService` is embedded in `.rdata` (rva `0xB6D3718`) as
plain JS source. `validateImpl()` runs five checks, OR-ed into one `blocked` flag:

```js
const o = this.checkIntegrityDataPresent(l, d);      // "missing integrity data"
const n = this.checkIntegrityJwt(l, i, d);           // uid mismatch (key from integrity.dll)
const s = this.checkApplicationSigned(d);            // "application is not signed" (app.isSigned())
const c = this.checkAsarIntegrityEnabled(d);         // "asar integrity fuses disabled"
const g = this.checkAsarIntegritySignature(d, l, i); // RS256 token + asarGlobalHash mismatch
```

and its caller aborts startup when the flag is set:

```js
const { appInfo: o, blocked: n, blockReason: s } = this.validationService.validate(e, t);
if (n) return this.loggerService.warn("[SECURITY] Browser validation failed. initialize() aborted"),
           void this.apiController?.close(`invalid verification (browser: ${s})`);
this._initialized = true;
```

The only escape hatch, `isDev = !app.isPackaged && integrityData.length === 0 &&
!appPath.includes(".asar")`, is unreachable for a packaged install — the three conditions
are mutually exclusive there.

**Note:** `_metadata.json`'s per-file sha256 values are *computed* in `readAsarData()` but
never compared inside `validateImpl()` — they are handed to `buildAppInfo()` as
`asarData`. Enforcement is entirely the fuse plus the five checks above.

---

## 5. The eight bytes

| # | site | offset | from → to | effect |
|---|---|---|---|---|
| 1 | `fuse.asar-integrity-validation` | `0x0B6C27A6` | `'1'` → `'0'` | Electron stops validating `app.asar` |
| 2 | `owepm.aggregate.present` | `0x0B6D2969` | `'0'` → `'1'` | `u=!0` → `u=!1` (integrity-data check cannot set blocked) |
| 3 | `owepm.aggregate.jwt` | `0x0B6D29B5` | `'0'` → `'1'` | same, JWT uid check |
| 4 | `owepm.aggregate.signed` | `0x0B6D2A02` | `'0'` → `'1'` | same, `app.isSigned()` check |
| 5 | `owepm.aggregate.fuse` | `0x0B6D2A52` | `'0'` → `'1'` | same, `isAsarIntegrityEnabled()` check |
| 6 | `owepm.aggregate.signature` | `0x0B6D2AA8` | `'0'` → `'1'` | same, RS256 + `asarGlobalHash` check |
| 7 | `owepm.aggregate.exception` | `0x0B6D2B2E` | `'0'` → `'1'` | the function's own `catch` no longer blocks |
| 8 | `owepm.fatalCatch` | `0x0B6D270F` | `'0'` → `'1'` | the outer `validate()` catch returns `blocked:!1` |

Each `u=!0` → `u=!1` is a single-character swap, so the JS stays syntactically intact and
the surrounding `!u && …` short-circuits all re-arm — every check still *runs* (and still
logs), it just can no longer set the flag.

**Matcher:** each site is anchored on its own unique 34–45 character context string, not on
a bare `u=!0,p=` — the pristine binary already contains one unrelated `u=!1,p=` at
`0x0B6D28AA`, which would make a naive pattern count ambiguous. Every site must resolve to
exactly one candidate in either its original *or* patched form, and any unexpected byte
value aborts the run with no write.

---

## 6. Verification

Round-trip on the real install, all through the shipped script:

```
Status  -> build PRISTINE, 0/8 patched,  sha c1d3f36d…
Apply   -> 8 bytes written, post-write re-read confirms 8/8, sha cc94512f…
Status  -> build PATCHED,   8/8 patched, sha cc94512f…
Revert  -> restored from backup (backup sha re-checked first), sha c1d3f36d…
Status  -> build PRISTINE, 0/8 patched
Apply   -> sha cc94512f…   (byte-identical to the first apply — deterministic)
```

Live boot of the **patched** launcher:

* 8 processes alive 22 s after launch, main window `Home - Lunar Client`, `Responding=True`
* full startup path ran — `[Metadata]`, `[Window] Renderer ready for window 'main'`,
  `[DiscordRP] Client has connected!`
* **0 hits** for `SECURITY` / `validation blocked` / `invalid verification` / `integrity`
  across every file in `%USERPROFILE%\.lunarclient\logs\launcher\*.log`

That proves the seven JS byte-swaps still parse and the validator no longer blocks. What it
does **not** yet prove is that a *modified* asar boots — that A/B test belongs to stage 2,
because stage 1 ships without touching the asar at all.

---

## 7. Limits

* **The updater will undo it.** Lunar replaces `Lunar Client.exe` on any new release;
  re-run `patch-now.cmd` after each update (the matcher will fail hard on an unknown build
  rather than write at stale offsets).
* **Authenticode is left as-is.** The exe is still signed with Overwolf/Moonsworth's
  certificate over the *original* bytes, so the signature no longer matches the file on
  disk. Windows does not care for normal execution; SmartScreen may prompt on first run of
  a freshly downloaded copy.
* **Mojang still owns the account question.** Nothing in this patch makes an unowned
  account work.
* No scheduled tasks, no watchers, no service, no registry writes — manual mode only.

---

## 8. Stage 2 — the Minecraft ownership gate (not shipped yet)

With the asar writable, the next gate is application-level, in
`resources\app.asar\dist-electron\electron\main.js` (5,754,280 bytes), on the launch path:

```js
LR = async e => {
  const r = await axios.get('https://api.minecraftservices.com/entitlements/license', {
    headers: { Authorization: `Bearer ${e}` }
  });
  return r.data.items.some(x => x.name === 'product_minecraft' || x.name === 'game_minecraft');
};
// launch pipeline:
if ([r, e] = await this.executeWithAccessToken(r, async e => LR(e.accessToken)), !e)
  throw new vR(SR.NO_OWNERSHIP, `This Microsoft account has not purchased Minecraft: Java Edition.`);
const { username: t, uuid: n, nameChangeData: i, attributes: a } = await zR(r.accessToken, r.remoteId);
if (a?.privileges.multiplayerServer === !1) throw new vR(SR.NO_MULTIPLAYER_ACCESS, ...);
if (a?.bannedScopes.some(...))                    throw new vR(SR.BANNED, ...);
```

Four things are needed and none of them are shipped here: neuter `LR`, synthesise `zR`'s
result instead of calling `api.minecraftservices.com`, keep the AssetServer client from
killing the launch, and inject a schema-valid entry into
`%USERPROFILE%\.lunarclient\settings\game\accounts.json` (currently `{"accounts": {}}`,
masked against the `mEe` schema — an invalid shape is silently replaced with an empty one).

**What stage 2 can and cannot buy, stated plainly:**

| | |
|---|---|
| launcher starts without Microsoft sign-in | achievable |
| singleplayer, and `online-mode=false` servers | achievable — that is what any offline session gives you |
| multiplayer on online-mode servers | **not achievable** — the server calls `sessionserver.mojang.com` itself |
| Lunar AssetServer (friends, cosmetics, cloud mods) | **not achievable** — Lunar's own server rejects the session with `NO_OWNERSHIP` / `NO_MULTIPLAYER_ACCESS` |
| skin upload to Mojang | **not achievable** — needs a real access token |

Nothing in stage 1 or 2 removes the requirement itself: that is Mojang's server-side
entitlement check, and the launcher is only the messenger that reports it.
