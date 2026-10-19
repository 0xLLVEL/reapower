# Lunar Client — Integrity Gate + Ownership Gate Unlock

Local patcher for the **Lunar Client launcher** (Moonsworth LLC, `lunarclient` **3.7.25-ow**,
Electron **42.7.1**). Two stages, both shipped:

* **Stage 1** removes the launcher's self-integrity gate: Electron's *asar-integrity* fuse is
  blown off and the Overwolf `owepm` validator can no longer block startup, so
  `resources\app.asar` becomes editable.
* **Stage 2** removes the launcher's Minecraft-ownership gate: two length-preserving edits
  inside `app.asar\dist-electron\electron\main.js` plus one fake entry in
  `accounts.json`. The launcher then starts as an account that does not exist, shows
  `LAUNCH GAME`, and reaches the end of its auth pipeline.

Everything here operates on your own installation, on disk, with no network calls.
It is an analysis of a shipped native/JS binary and a byte-level patch of it:
**8 bytes of the 235,252,216-byte exe differ**, and **432 bytes inside the 5,754,280-byte
`main.js` differ while its total length stays exactly the same** — which is why the asar
header never has to be rebuilt.

---

## Table of contents

1. [Target / verified build](#1-target--verified-build)
2. [TL;DR — usage](#2-tldr--usage)
3. [What it does / what it does NOT do](#3-what-it-does--what-it-does-not-do)
4. [How Lunar's integrity gate actually works](#4-how-lunars-integrity-gate-actually-works)
5. [The patches](#5-the-patches)
6. [Verification](#6-verification)
7. [Limits](#7-limits)
8. [Stage 2 — the Minecraft ownership gate](#8-stage-2--the-minecraft-ownership-gate)

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
| companion | `integrity.dll` 13,840 B (Overwolf public-key carrier), `owutility.dll` 3,107,984 B (Overwolf Electron Utility 0.0.0.56) — untouched; `resources\app.asar` 25,797,518 B is untouched by stage 1 and is the stage 2 target (sha256 pristine `40C41720…`, patched `4334600F…`) |

A different Lunar build gets different offsets. The matcher fails hard instead of guessing:
see [§5](#5-the-eight-bytes).

---

## 2. TL;DR — usage

```
status.cmd           report pristine / patched / unknown + the 8 exe site states
patch-now.cmd        back up the pristine exe, write the 8 bytes, verify by re-reading
revert.cmd           restore the pristine exe from the backup (sha-checked before restore)

stage2-status.cmd    report the asar build, the 2 main.js spans and accounts.json
patch-stage2.cmd     back up app.asar + accounts.json, write the 2 spans, verify by sha
revert-stage2.cmd    restore the pristine app.asar + accounts.json from backup
```

Close the launcher first — the script refuses to touch a running instance.

Both stages are independent but stage 2 is useless without stage 1: with the fuse on,
any edit to `app.asar` aborts startup before a single line of `main.js` runs.

---

## 3. What it does / what it does NOT do

**Stage 1 does:**

* Blows Electron's `enableEmbeddedAsarIntegrityValidation` fuse **off**, so Electron stops
  re-hashing `app.asar` at load time.
* Neutralises the Overwolf `owepm` validator so it can no longer return `blocked: true` —
  which was the thing that aborted startup with
  `invalid verification (browser: …)`.
* Leaves a byte-identical pristine backup and restores it on `-Mode Revert`.

**Stage 2 does:**

* Replaces `LR` — the entitlements check against `api.minecraftservices.com` — with a
  constant `true`, which kills both `NO_OWNERSHIP` throws on the launcher's code paths.
* Replaces the launch pipeline's `await zR(accessToken, remoteId)` — the profile +
  privileges fetch from Mojang — with a literal object built out of `accounts.json`,
  with `attributes: undefined` so the multiplayer and ban checks short-circuit.
* Writes a schema-valid fake account into `accounts.json`, with a far-future token expiry
  so the launcher never tries to refresh it.
* Verifies the rebuilt asar by sha256 **before** writing, and restores both files from
  backup on `-Mode Stage2Revert`.

**Neither stage does:**

* Does **not** grant multiplayer on online-mode servers — the server calls
  `sessionserver.mojang.com` itself, and no local patch reaches it.
* Does **not** unlock Lunar's own network (friends, cosmetics, cloud mods) — Lunar's
  AssetServer rejects the fake session with `no-account`, every 30 s, harmlessly.
* Does **not** touch the Authenticode signature, the registry, or anything outside the
  exe, `app.asar`, `accounts.json` and the backup directory.

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

## 5. The patches

### 5a. Stage 1 — the eight bytes

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

### 5b. Stage 2 — the two spans in `main.js`

`app.asar` is a 16-byte pickle header, a 347,756-byte JSON tree, then packed file data.
`dist-electron/electron/main.js` sits at data offset `4939`, is 5,754,280 bytes long, and
every other entry's offset is relative to the same base — so **a net-zero length edit inside
`main.js` keeps the whole archive valid**. No rebuild, no header rewrite, no re-hash.

| # | site | offset in `main.js` | span | effect |
|---|---|---|---|---|
| 1 | `auth.LR.ownership-check` | `0x21C38C` | 398 → 331 chars | `LR` (the `entitlements/license` GET) becomes `async e=>!0` |
| 2 | `launch.profile-call` | `0x33FF32` | 34 → 101 chars | `await zR(r.accessToken,r.remoteId)` becomes an object literal from `accounts.json` |

The 67 characters site 2 grows are eaten by the comment pad site 1 sheds, so
`main.js` is still 5,754,280 bytes and the asar is still 25,797,518 bytes.

```
site 1 : LR=async e=>!0/*stage2: ownership gate disabled (LR)        */,
site 2 : {username:r.minecraftProfile.name,uuid:r.minecraftProfile.id,nameChangeData:void 0,attributes:void 0}
```

Site 2 is deliberately **not** a patch of `zR`'s definition — `zR` is also called by
`completeMcLogin`, the real Microsoft sign-in path, and rewriting its body would corrupt
sign-in for a genuine account. Patching the single launch call site leaves that path intact.

`attributes: undefined` is not laziness, it is the exact value Lunar itself produces when
the privileges request fails (that call has a `.catch` that swallows). Both consumers are
optional-chained — `a?.privileges.multiplayerServer === !1` and `a?.bannedScopes.some(…)`
— so `undefined` walks straight past the `NO_MULTIPLAYER_ACCESS` and `BANNED` throws.

**Matcher:** each span is located by its own unique anchor (`LR=async e=>{let t=IR();` and
`await zR(r.accessToken,r.remoteId)`), then the full span is sliced and hashed against the
recorded sha256 of the known build. A hit on the anchor with a different span hash aborts.
The rebuilt asar's sha256 is compared against the recorded value **before** anything is
written, so a wrong result is caught with the original file still intact.

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

That proves the seven JS byte-swaps still parse and the validator no longer blocks.

### The A/B test — is the gate load-bearing?

Same machine, same day, only the two variables that matter:

| | exe | asar | result |
|---|---|---|---|
| A (control) | pristine | pristine | 8 processes alive, 10 log files written, window up |
| A (test) | pristine | **patched** | **exit code 1, 0 processes, 0 log files** — dies before the logger even initialises |
| B | **patched** | **patched** | 7 processes alive, window `Home - Lunar Client` |

A's two rows differ in one variable only, so the abort is the integrity gate doing exactly
what §4 says it does: with the fuse on, a modified asar kills the app. Stage 1 is therefore
load-bearing and not cosmetic.

### Stage 2 round-trip

```
Stage2Status -> build PRISTINE, both spans original, accounts 0 entries
Stage2Apply  -> asar sha 40c41720… -> 4334600f…, both spans patched, accounts 1 entry
Stage2Status -> build PATCHED, 2/2 spans, accounts.json valid, expiry in the future
Stage2Revert -> asar sha 40c41720…, accounts.json back to 0 entries
Stage2Apply  -> asar sha 4334600f…   (byte-identical to the first apply — deterministic)
```

### Stage 2 live boot (test B)

`%USERPROFILE%\.lunarclient\logs\launcher\auth.log`, untouched, in order:

```
[Auth] Account Ratman4080 is currently active
[Auth] Validating account Ratman4080 owns Minecraft...
[Auth] Account Ratman4080 successfully validated to own Minecraft, proceeding with profile retrieval...
[Auth] Successfully retrieved Minecraft profile for account Ratman4080, checking multiplayer privileges...
[Auth] Successfully validated account Ratman4080 owns Minecraft, checking banned status...
[Auth] Account Ratman4080 has multiplayer access and is not banned, proceeding with login...
```

All six lines, in 11 ms, against `api.minecraftservices.com` — which was never contacted.
No `Accounts file is invalid, creating new one...` (the `hEe`/`mEe` mask accepted the fake
entry), no `[SECURITY]`, no `validation blocked`, no `NO_OWNERSHIP`.

The renderer confirms it: title bar reads `Ratman4080`, the page greets
`Welcome Back Astronaut, Ratman4080`, and the big green button reads
**LAUNCH GAME — Lunar Client 26.3 with Fabric**. No sign-in wall, no "you must own
Minecraft" dialog.

What the launcher logs also show, and this is expected rather than a problem:

```
[AssetServer] No reconnect JWT available, going to Authenticator...
[AssetServer] An unexpected error occurred while authenticating with Lunar Client:
              No account found for getting Lunar Client Token (no-account)
[AssetServer] Scheduling reconnect task...      (then every 30 s, forever, harmlessly)
```

That is Lunar's own network rejecting the fake session. It is caught, logged, and retried
with backoff — it never touches the launch path.

**Not yet run:** the game itself through Lunar (downloading the client and starting a
`javaw` instance). The launcher gate is closed and proven; the game-side session is a
separate question and one download away.

---

## 7. Limits

* **The updater will undo both stages.** Lunar replaces `Lunar Client.exe` and
  `resources\app.asar` on any new release; re-run `patch-now.cmd` then `patch-stage2.cmd`
  after each update. Both matchers fail hard on an unknown build rather than write at stale
  offsets.
* **Authenticode is left as-is.** The exe is still signed with Overwolf/Moonsworth's
  certificate over the *original* bytes, so the signature no longer matches the file on
  disk. Windows does not care for normal execution; SmartScreen may prompt on first run of
  a freshly downloaded copy. `app.asar`'s embedded per-file SHA256 blocks in the asar header
  are also now stale — that is exactly what the blown fuse stops Electron from checking.
* **The fake account is not a Minecraft account.** It is a launcher-local record. Mojang has
  never heard of `9f8e7d6c5b4a39281706f5e4d3c2b1a0` and nothing here changes that.
* **Online-mode multiplayer stays closed.** The server, not the client, calls
  `sessionserver.mojang.com`. Same for Realms, chat reporting, Mojang-side skins, and
  anything on Lunar's own network.
* **Re-applying over an already-patched asar is a different code path** than applying over a
  pristine one: the rebuilt segment has to pass the two existing spans *through* instead of
  replacing them. An earlier version of the script dropped them and the net-zero assertion
  caught it before any write (`net-zero violated: rebuilt main.js is 5753848 bytes`). Fixed;
  `-Mode Stage2Apply` is now idempotent and re-verifies to the same `4334600f…` sha.
* **One observed `accounts.json` wipe.** In a single boot — the one immediately after force-
  killing seven launcher processes — the launcher came up with `No accounts found, setting to
  guest mode...` and left `{"accounts": {}}` behind, and quit itself 29 s later. It did not
  reproduce: a clean re-run polled the file every 3 s for 43 s across a full boot and it
  never moved off 739 bytes. Treat it as a hazard of killing a live instance rather than a
  steady state, and check `-Mode Stage2Status` after any unclean shutdown — it reports the
  entry count, and `0 entry/entries` while the asar reads `PATCHED` means re-run Apply.
* No scheduled tasks, no watchers, no service, no registry writes — manual mode only.

---

## 8. Stage 2 — the Minecraft ownership gate

The launcher's launch pipeline, from `app.asar\dist-electron\electron\main.js`:

```js
LR = async e => {                                   // <- site 1, 398 chars
  const t = axios.get('https://api.minecraftservices.com/entitlements/license', {
    headers: { Authorization: `Bearer ${e}` },
    params: { requestId: randomUUID() }
  });
  return (await t).data.items.some(x => x.name === 'product_minecraft' || x.name === 'game_minecraft');
};
// launch pipeline:
if ([r, e] = await this.executeWithAccessToken(r, async e => LR(e.accessToken)), !e)
  throw new vR(SR.NO_OWNERSHIP, `This Microsoft account has not purchased Minecraft: Java Edition.`);
const { username: t, uuid: n, nameChangeData: i, attributes: a } =
  await zR(r.accessToken, r.remoteId);              // <- site 2, 34 chars
if (a?.privileges.multiplayerServer === !1) throw new vR(SR.NO_MULTIPLAYER_ACCESS, ...);
if (a?.bannedScopes.some(...))                      throw new vR(SR.BANNED, ...);
```

Site 1 makes the entitlements check return `true` without leaving the process. Site 2 stops
the profile/privileges fetch from reaching Mojang at all and hands the pipeline a literal
built from `accounts.json`. The remaining failure mode is upstream of both:
`executeWithAccessToken` refreshes the token when `dayjs(accessTokenExpiresAt).isBefore(now)`,
and `refreshAccountInternal` throws `INVALID_SESSION` when the refresh token is fake — so the
written account carries `2099-12-31T23:59:59.999Z` and a non-empty `refreshToken` (an empty
one also makes the UI flag the account invalid, because `initAuthInternal` sets
`invalid: !e.refreshToken`).

### The fake account

`%USERPROFILE%\.lunarclient\settings\game\accounts.json`, read by `AR()` and masked against
`hEe` / `mEe` — a shape mismatch is silently replaced with `{"accounts": {}}`, which is why
the schema is mirrored exactly, including the fields Lunar's own `_Ee` writes:

```json
{
  "accounts": {
    "7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4": {
      "accessToken": "stage2-offline-access-token",
      "accessTokenExpiresAt": "2099-12-31T23:59:59.999Z",
      "localId": "7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4",
      "refreshToken": "stage2-offline-refresh-token",
      "minecraftProfile": { "id": "9f8e7d6c5b4a39281706f5e4d3c2b1a0", "name": "Ratman4080" },
      "remoteId": "7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4",
      "type": "Xbox",
      "username": "Ratman4080",
      "eligibleForMigration": false,
      "hasMultipleProfiles": false,
      "legacy": false,
      "persistent": true,
      "userProperties": []
    }
  },
  "activeAccountLocalId": "7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4"
}
```

`minecraftProfile.id` must be 32 lowercase hex — `pN()` dashes it on the way out and `mN()`
strips it on the way back, and both compare against that shape.

It must **also look like a random v4 UUID**, which is a nastier trap than it sounds:

```js
fN = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|...)$/i
mN = e => fN.test(e) ? e.replace(/-/g, ``) : e
```

`mN()` only strips the dashes `pN()` added **if the dashed form passes a strict v4 check** —
version nibble `4`, variant nibble `[89ab]`. `getAccount(dashedId)` compares the result
against the *undashed* `minecraftProfile.id`, so a non-v4 id makes the lookup miss and the
AssetServer client aborts with `SR.NO_ACCOUNT` before it ever opens a socket:

```
[AssetServer] An unexpected error occurred while authenticating with Lunar Client:
              No account found for getting Lunar Client Token (no-account)
```

An id like `9f8e7d6c5b4a3928…` has version nibble `3` and variant nibble `1` — it fails `fN`.
`9f8e7d6c5b4a4928…` passes. With the v4-shaped id the launcher gets all the way to Lunar's
real authenticator:

```
[Auth] [Authenticator] Connection opened for Ratman4080 (…)
[Auth] [Authenticator] Creating Minecraft session for Ratman4080 (…)
[Auth] [Authenticator] Failed to create Minecraft session: Failed to create Minecraft session (mc-create-session)
[Auth] [Authenticator] Connection disconnected … Code: 1000 - Reason: Failed encryption (…)
```

That is the last wall on this path: `mc-create-session` is the launcher proxying
`login_with_xbox` + session join to Mojang with a token that does not exist. Everything
before it — local account, entitlements gate, profile gate, WebSocket handshake to
`wss://authenticator.lunarclientprod.com/launcher-v3` — now succeeds.

### What stage 2 buys, stated plainly

| | |
|---|---|
| launcher starts and identifies as an account without Microsoft sign-in | **shipped, verified** |
| `LAUNCH GAME` button present, auth pipeline completes | **shipped, verified** |
| singleplayer, and `online-mode=false` servers | achievable — that is what any offline session gives you |
| multiplayer on online-mode servers | **not achievable** — the server calls `sessionserver.mojang.com` itself |
| Lunar AssetServer (friends, cosmetics, cloud mods) | **not achievable** — Lunar's own server rejects the session with `no-account` |
| skin upload to Mojang | **not achievable** — needs a real access token |

Nothing in stage 1 or 2 removes the requirement itself: that is Mojang's server-side
entitlement check, and the launcher is only the messenger that reports it. What these two
stages remove is the launcher's willingness to deliver that message.

### Known behaviour change

Site 1 is global: `LR` is also called by `completeMcLogin`, the genuine Microsoft sign-in
path. With the patch in place a real account would skip the ownership check at sign-in too.
That path is otherwise untouched — a real token still flows through `zR`, the privileges and
ban checks, and the AssetServer handshake.

### Revert

`revert-stage2.cmd` restores `app.asar` from
`%LOCALAPPDATA%\LunarPatch\backup\app.asar.pristine` (sha-checked first) and
`accounts.json` from `accounts.json.pristine`. `revert.cmd` does the same for the exe. The
two stages revert independently.
