# Lunar Client — Integrity Gate + Ownership Gate Unlock

Local patcher for the **Lunar Client launcher** (Moonsworth LLC, `lunarclient` **3.7.25-ow**,
Electron **42.7.1**), plus one Fabric mod. Three stages, all shipped:

* **Stage 1** removes the launcher's self-integrity gate: Electron's *asar-integrity* fuse is
  blown off and the Overwolf `owepm` validator can no longer block startup, so
  `resources\app.asar` becomes editable.
* **Stage 2** removes the launcher's Minecraft-ownership gate: two length-preserving edits
  inside `app.asar\dist-electron\electron\main.js` plus one fake entry in
  `accounts.json`. The launcher then starts as an account that does not exist, shows
  `LAUNCH GAME`, and reaches the end of its auth pipeline.
* **Stage 3** is a Fabric mod that injects `PlayerCosmeticsPushV2` locally, so cosmetics
  render without Lunar's AssetServer ever issuing a JWT.

Stages 1 and 2 operate on your own installation, on disk, with no network calls: an analysis
of a shipped native/JS binary and a byte-level patch of it — **8 bytes of the
235,252,216-byte exe differ**, and **432 bytes inside the 5,754,280-byte `main.js` differ
while its total length stays exactly the same** — which is why the asar header never has to
be rebuilt. Stage 3 touches nothing on disk outside the `mods` folder.

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
9. [Stage 3 — cosmetics without the AssetServer](#9-stage-3--cosmetics-without-the-assetserver)

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
see [§5](#5-the-patches).

---

## 2. TL;DR — usage

```
status.cmd           report pristine / patched / unknown + the 8 exe site states
patch-now.cmd        back up the pristine exe, write the 8 bytes, verify by re-reading
revert.cmd           restore the pristine exe from the backup (sha-checked before restore)

stage2-status.cmd    report the asar build, the 2 main.js spans and accounts.json
patch-stage2.cmd     back up app.asar + accounts.json, write the 2 spans, verify by sha
revert-stage2.cmd    restore the pristine app.asar + accounts.json from backup

account-manager.ps1  list / show / add / use / remove / refresh / validate the accounts
mod\                 stage 3 source; build -> rat-cosmetics.jar (see §9)
```

Close the launcher first — the script refuses to touch a running instance.

Both stages are independent but stage 2 is useless without stage 1: with the fuse on,
any edit to `app.asar` aborts startup before a single line of `main.js` runs.

`patch-stage2.cmd` must be re-run whenever `accessTokenExpiresAt` lapses — it is written as
`now + 12h`, see [§8](#8-stage-2--the-minecraft-ownership-gate).

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
* Does **not** unlock Lunar's own network (friends, cloud mods) — Lunar's AssetServer
  rejects the fake session with `no-account`, every 30 s, harmlessly. **Cosmetics is the one
  exception**: they are not gated by the session at all, so stage 3 restores them locally
  without defeating that rejection — see [§9](#9-stage-3--cosmetics-without-the-assetserver).
* Does **not** touch the Authenticode signature, the registry, or anything outside the
  exe, `app.asar`, `accounts.json` and the backup directory.

**Stage 3 does:**

* Fabric mod `rat-cosmetics.jar`, dropped in `profiles\<ver>\mods\fabric-26.3\`. A daemon
  thread re-injects a synthetic `PlayerCosmeticsPushV2` every 3 s, straight into the two
  entry points the real AssetServer push would call. Zero network calls — it reads only
  `bridge$getSession()`, the world, and the local profile.

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

### The game — boot, render, main menu

**Run.** The launcher downloads the client, starts a `javaw` against the bundled JRE
(`%USERPROFILE%\.lunarclient\jre\515e47c1…\zulu25.30.17-ca-jre25.0.1-win_x64`), and the game
reaches the main menu as **Ratman4080** — account chip, Lunar logo menu, Singleplayer /
Multiplayer / Discover / Store, `Lunar Client 26.3 (v2.23.5-2643)`.

The `(2)` wall that used to reject the account is gone from `latest.log`, replaced by the
normal load sequence:

```
[LC Accounts] Attempting to load account [7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4]
[LC Accounts] Loaded content for [Ratman4080] Token IAT
[LC Accounts] Setting currentAccount to what was on disk: Ratman4080
[LC Accounts] Setting account 'Ratman4080' as the current session.
[LC Accounts] Removed all accounts [0 count]
```

The last line is not a failure: `Removed all accounts` reports what was in the map *before*
the add, and `[0 count]` is why `accounts.json` can legitimately read `{"accounts": {}}`
— see [§8](#8-stage-2--the-minecraft-ownership-gate).

The game-side session failure that remains is expected and does not block anything playable:

```
[LC Auth] Invalid Session
com.mojang.authlib.exceptions.InvalidCredentialsException: ForbiddenOperationException
  at MinecraftServicesSessionService.joinServer      (retries at 30 s backoff)
```

That is Mojang's `joinServer` refusing a token that was never issued. It blocks online-mode
multiplayer only — not the menu, not singleplayer, not `online-mode=false` servers, and not
cosmetics (§9).

### Stage 3 — cosmetics render

`rat-cosmetics.log`, in order:

```
NOTREADY root=null                 <- thread woke before the client finished init
NOTREADY mgr=false disp=false      <- root resolved, child services still coming up
OK ids=[3, 2424, 894] uuid=9f8e7d6c-5b4a-4928-9706-f5e4d3c2b1a0
```

`OK` is written only after **both** injection calls return without throwing, and there is no
`ERR` line. In-game, cosmetic id 3 (*Lunar Client Classic*) renders on the character's back,
and the nametag badge takes `setLogoColor(0x55FFFF)` — so the dispatcher path and the manager
handler both landed, not just one.

---

## 7. Limits

* **The updater will undo both stages.** Lunar replaces `Lunar Client.exe` and
  `resources\app.asar` on any new release; re-run `patch-now.cmd` then `patch-stage2.cmd`
  after each update. Both matchers fail hard on an unknown build rather than write at stale
  offsets. Stage 3's jar survives an updater run untouched, but a new **Minecraft** version
  means a new profile directory (`profiles\26\mods\fabric-26.3` → `27\…`), so the jar has to
  be copied into the new one — and the obfuscated entry-point names in §9 are build-specific
  and will need re-mining against the new `lunar.jar`.
* **Authenticode is left as-is.** The exe is still signed with Overwolf/Moonsworth's
  certificate over the *original* bytes, so the signature no longer matches the file on
  disk. Windows does not care for normal execution; SmartScreen may prompt on first run of
  a freshly downloaded copy. `app.asar`'s embedded per-file SHA256 blocks in the asar header
  are also now stale — that is exactly what the blown fuse stops Electron from checking.
* **The fake account is not a Minecraft account.** It is a launcher-local record. Mojang has
  never heard of `9f8e7d6c5b4a49289706f5e4d3c2b1a0` and nothing here changes that.
* **Online-mode multiplayer stays closed.** The server, not the client, calls
  `sessionserver.mojang.com`. Same for Realms, chat reporting, Mojang-side skins, and the
  rest of Lunar's own network — cosmetics being the single exception, restored locally by
  stage 3 rather than by defeating that check.
* **The account's timestamp has a 14-day shelf life.** `accessTokenExpiresAt` is written as
  `now + 12h`, because Lunar's `load()` rejects anything more than 14 days ahead of now
  (§8). After 12 hours the launcher sees a lapsed token and attempts a refresh that cannot
  succeed — re-run `patch-stage2.cmd` to rewrite it. `-Mode Stage2Status` reports the
  remaining window.
* **Re-applying over an already-patched asar is a different code path** than applying over a
  pristine one: the rebuilt segment has to pass the two existing spans *through* instead of
  replacing them. An earlier version of the script dropped them and the net-zero assertion
  caught it before any write (`net-zero violated: rebuilt main.js is 5753848 bytes`). Fixed;
  `-Mode Stage2Apply` is now idempotent and re-verifies to the same `4334600f…` sha.
* **The `accounts.json` wipe is the `(2)` reject, not a race.** The mechanism (§8): a
  rejected account is `remove`d from the map before `map.put` ever runs, so the map stays
  empty, and the next flush writes out `{"accounts": {}}` — the *correct* serialisation of
  an empty map. What made it look like a corruption bug is that it happened in the boot
  right after seven launcher processes were force-killed, which pointed at a race; it does
  not. `-Mode Stage2Status` reports the entry count, and `0 entry/entries` while the asar
  reads `PATCHED` means the timestamp went stale — re-run Apply.
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
and `refreshAccountInternal` throws `INVALID_SESSION` when the refresh token is fake. So the
timestamp must be in the future — but *not* arbitrarily far in the future, because of the
`(2)` check below. `refreshToken` must also be non-empty: an empty one makes the UI flag the
account invalid, because `initAuthInternal` sets `invalid: !e.refreshToken`.

### The fake account

`%USERPROFILE%\.lunarclient\settings\game\accounts.json`, read by `AR()` and masked against
`hEe` / `mEe` — a shape mismatch is silently replaced with `{"accounts": {}}`, which is why
the schema is mirrored exactly, including the fields Lunar's own `_Ee` writes. This is the
live file as `patch-stage2.cmd` writes it:

```json
{
  "activeAccountLocalId": "7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4",
  "accounts": {
    "7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4": {
      "accessToken": "stage2-offline-access-token",
      "accessTokenExpiresAt": "2026-10-20T09:21:26.368Z",
      "eligibleForMigration": false,
      "hasMultipleProfiles": false,
      "legacy": false,
      "persistent": true,
      "localId": "7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4",
      "refreshToken": "stage2-offline-refresh-token",
      "minecraftProfile": {
        "id": "9f8e7d6c5b4a49289706f5e4d3c2b1a0",
        "name": "Ratman4080"
      },
      "remoteId": "7a1f0c3b-5d9e-4f68-a2b7-c1d0e3f5a9b4",
      "type": "Xbox",
      "username": "Ratman4080"
    }
  }
}
```

`accessTokenExpiresAt` is **not** a constant — `$S2ExpiresAt` computes
`(now).ToUniversalTime().AddHours(12)` at apply time. The reason for `now + 12h` rather than
a far-future date is the `(2)` check below; `2099-12-31` fails it.

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

### The `(2)` check — why the expiry is `now + 12h`

`AccountManager.load()` has exactly one way to reject an account *after* the schema mask has
accepted it. Bytecode, `AccountManager` at `cp#216` → `cp#267`, with the success label
`281` and the reject at `246`:

```
216  invokevirtual  <acct>.IRHCCOHIOOORRRIRCRIOCHRHCIIORR()  Instant   ; the account's timestamp
219  astore 9
221  aload 9
223  ifnull  -> 281                                 ; null passes outright
226  aload 9                                        ; receiver: the account timestamp
228  invokestatic   time/Instant.now()
231  ldc2_w         14L
234  getstatic      temporal/ChronoUnit.DAYS
237  invokevirtual time/Instant.plus(J,TemporalUnit) ; now.plus(14, DAYS)
240  invokevirtual time/Instant.isAfter(Instant)     ; <acct>.isAfter(now + 14d)
243  ifeq  -> 281                                    ; false -> accept
246  ldc   "Account [%s] was invalid (2)"             ; true  -> REJECT
264  invokevirtual <mgr>.COCHCHCHCIOCIOOCIIIIHCHRORHCIO()  Map   ; accountsMap.remove(<acct>)
281  ldc   "Loaded content for [%s] Token IAT"        ; accept label
```

The receiver order is the whole point: `aload 9` pushes the account timestamp *before*
`now`, `14L` and `DAYS`, so `plus` has `now` as its receiver and `isAfter` has the account
timestamp as its — reading it as `now.plus(14, DAYS).isAfter(<acct>)` inverts the rule and
yields a completely different (and unsatisfiable) requirement.

Read straight, the rule is:

> **Reject when `<acct> > now + 14 days`.**

There is no lower bound in this check — a timestamp in the past is fine here. But a past
timestamp is rejected one stage earlier, by `executeWithAccessToken`'s refresh trigger.
The usable window is therefore bounded on both ends, and `now + 12h` sits comfortably inside
it:

| written value | `<acct> > now+14d` → `(2)` | `dayjs(...).isBefore(now)` → refresh | outcome |
|---|---|---|---|
| `2099-12-31T23:59:59.999Z` | **yes** | no | rejected, removed |
| `(now - 30d)` | no | **yes** | `INVALID_SESSION` on refresh |
| `now + 12h` | no | no | **accepted** |

That first row was the original value shipped in this account, and it is the answer to both
open questions from §7: the `Account [%s] was invalid (2)` line, and the `accounts.json`
wipe. The wipe is not a race and not corruption — it is the correct serialisation of a map
the reject emptied:

```java
if (iat.isAfter(Instant.now().plus(14, ChronoUnit.DAYS))) {
    log("Account [%s] was invalid (2)", username);
    accountsMap.remove(username);   // removed before put is ever reached
    continue;
}
...
map.put(username, account);        // skipped for the rejected account
// map is still empty -> next flush writes {"accounts": {}}
```

`{"accounts": {}}` is exactly what `{"accounts": {}}` should look like when nothing was
inserted. With `now + 12h` the account reaches the `281` label and the normal load sequence
runs — see the `Loaded content for [Ratman4080] Token IAT` line in §6.

The cost of the 12-hour ceiling is honest and small: re-run `patch-stage2.cmd` when
`-Mode Stage2Status` reports the window has expired, or the launcher will attempt the
refresh that `INVALID_SESSION` blocks.

### Managing the accounts

`account-manager.ps1` operates on the same file, and every constraint it enforces comes from
the bytecode above — it is not opinion, it is `load()` reading the file.

| Mode | Effect |
|---|---|
| `List` | table of every account: active marker, expiry window and time left, v4 check, refresh token, uuid, key |
| `Show -Name X` | one account in full, plus its violations |
| `Add -Name X` | new account: random v4 uuid, random v4 `localId`/`remoteId`, expiry `now + $ExpiresHours` |
| `Use -Name X` | set `activeAccountLocalId` |
| `Remove -Name X` | delete; reassigns `active` to another account; refuses to remove the last one |
| `Refresh [-Name X]` | set expiry to `now + $ExpiresHours` |
| `Validate` | violations only, and **throws** on any `FAIL` so it is scriptable |
| `Backup` / `Restore` | snapshot to `%LOCALAPPDATA%\LunarPatch\backup\accounts.manager.json` |

`-ExpiresHours` defaults to 12. `-AccountsPath` and `-BackupDir` default to the live file and
the real backup dir; pointing both at a directory makes the whole thing a sandbox, which is
how every mode above was tested — the live file was never written during verification.

Writing modes refuse to run while `Lunar Client.exe` is up **when the target is the live
file**. The launcher rewrites `accounts.json` on exit, so a write racing it is lost; a
sandbox copy cannot be raced by anything, so it is allowed at any time.

#### The schema is the launcher's output, not the script's

`patch-stage2.cmd` stamps `"userProperties": []` into `accounts.json` and puts `accounts`
first. The live file has no `userProperties` at all and puts `activeAccountLocalId` first —
because `hEe`/`mEe` parse it and re-serialise it, and the valibot mask silently drops keys it
does not know. So the file Lunar writes is the ground truth for what the file must contain,
and `account-manager.ps1` emits exactly that shape, round-trip stable.

#### Violation codes

`List` and `Validate` report them; only `FAIL` blocks.

| Code | Severity | Consequence |
|---|---|---|
| `(2).window` | FAIL | expiry past `now + 14d` → `load()` removes the account before `map.put`, and the next flush writes `{"accounts": {}}` |
| `profile.id.shape` | FAIL | not 32 lowercase hex → the valibot mask discards the whole file |
| `profile.missing` | FAIL | no `minecraftProfile` → same |
| `username.empty` | FAIL | the dup check and the load log both key on it |
| `key.localid` | FAIL | map key does not equal `localId` |
| `active.missing` / `active.dangling` | FAIL | no usable `activeAccountLocalId` |
| `expiry.past` | WARN | `executeWithAccessToken` fires `refreshAccountInternal` → `INVALID_SESSION` |
| `profile.id.notv4` | WARN | `mN()` will not strip dashes → `getAccount()` misses → `SR.NO_ACCOUNT` |
| `refresh.empty` | WARN | `initAuthInternal` sets `invalid: !e.refreshToken`; the UI flags the account |
| `name.mismatch` | WARN | `username` != `minecraftProfile.name` |

#### `patch-stage2.cmd` no longer destroys them

Recovering from an updater run means re-running `patch-stage2.cmd`, which used to write its
template over `accounts.json` unconditionally — silently deleting anything the manager had
added. `Write-Accounts` now stamps the template **only** into a file that is missing,
unparseable or empty, which is the state a pristine install starts in and the state
`Stage2Revert` restores. Whatever is already there is kept, and only accounts whose expiry
has fallen outside `(now, now + 14d]` are refreshed.

Re-verified on a sandbox, live files untouched:

| Step | asar sha | accounts |
|---|---|---|
| start | `40c41720` | 0 |
| `Stage2Apply` | `4334600f` | 1 |
| `Stage2Revert` | `40c41720` | 0 |
| `Stage2Apply` | `4334600f` | 1 |

and with 2 accounts present, one of them poisoned to `2099-12-31T23:59:59.999Z`: 2 in, 2
out, the poisoned one refreshed to `now + 12h`, the in-window one untouched, asar sha still
`4334600f`.

### What stage 2 buys, stated plainly

| | |
|---|---|
| launcher starts and identifies as an account without Microsoft sign-in | **shipped, verified** |
| `LAUNCH GAME` button present, auth pipeline completes | **shipped, verified** |
| singleplayer, and `online-mode=false` servers | achievable — that is what any offline session gives you |
| multiplayer on online-mode servers | **not achievable** — the server calls `sessionserver.mojang.com` itself |
| cosmetics | **achieved** — but by stage 3, not by this table's mechanism; see §9 |
| Lunar AssetServer (friends, cloud mods) | **not achievable** — Lunar's own server rejects the session with `no-account` |
| skin upload to Mojang | **not achievable** — needs a real access token |

Nothing in stage 1 or 2 removes the requirement itself: that is Mojang's server-side
entitlement check, and the launcher is only the messenger that reports it. What these two
stages remove is the launcher's willingness to deliver that message. Stage 3 does not
defeat any check either — it supplies the payload the check would have authorised.

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

---

## 9. Stage 3 — cosmetics without the AssetServer

Lunar's cosmetics never arrive as an HTTP fetch. The launcher holds two sockets —
`pEe()` → `wss://authenticator.lunarclientprod.com/launcher-v3` and
`AL()` → `wss://websocket.lunarclientprod.com/launcher-v3` — and the second one pushes a
`PlayerCosmeticsPushV2` protobuf. That push is the *only* thing that populates the
equipped list. The JWT wall blocks it, which is why cosmetics die while singleplayer
does not.

But the push handler does not authenticate anything. It takes a protobuf, computes a
`PlayerState`, puts it in a map, and refreshes the HUD. Nothing in that path touches the
network. So the wall can be walked around entirely: build the same protobuf locally and
hand it to the same two methods the socket would have called.

All cosmetic **assets** are already on disk — only the *ownership list* was server-side.
`%USERPROFILE%\.lunarclient\textures\assets\lunar\cosmetics.json` is a catalog of
**5,676** items across 20 categories (`cloak` 2688, `hat` 499, `pet` 467, `bandanna` 449,
`dragon_wings` 419, …), each with an integer `id`.

### Why a Fabric mod and not a jar patch

The game already runs a real Fabric loader — `modrinth.index.json` in
`lunar-modpack.mrpack` declares `"fabric-loader": "0.19.5"`, and Lunar ships it as an
in-process fork (Ichor); no `fabric-loader.jar` exists anywhere under `.lunarclient`, and
`net/fabricmc/api/` has **0** entries in `lunar.jar`. So there is nothing to patch inside
the jar, but there *is* a mods directory being loaded from. A 5 KB mod on top of that
classpath is strictly less invasive than rewriting 69 MB of obfuscated bytecode.

### The chain — three hops, all bytecode-confirmed

```java
// 1. root
var root = com.moonsworth.lunar.client.util.RHCRCOORHOOCRRHRHCOHHICOHIIIHO
    .IRHOCRROOOIICOOCRRRIRHICOHICOC();          // invokestatic -> client/RRRRRIRCCIIORHHCCCHICOCRRCOOOH

// 2. both children come off the root, NOT off each other
root.HHRCCCROHCRHHOCRHCCRRORRIOCCOO();          // -> .../OOCHHCIRCOCHOOOCIOIIHCRIIHRRCH    (manager)
root.IRHOHHIIHICCIOIIRCCCCCHHIOCCRC();          // -> .../IICRCHHORRHHCIRROCHIRCRIOIORRC    (dispatcher)
```

The obvious chain — `root → manager → dispatcher` — **does not exist**: the manager declares
no method returning the dispatcher. It holds one as a field and calls straight into it, which
is why the first build died with
`NoSuchMethodException: …OOCHHCIRCOCHOOOCIOIIHCRIIHRRCH.CORRIROORHRIRIHCRHROIOCRCCIOIH`.
Both getters live on the root; `root_sigs.txt` and the first three instructions of
`AccountManager.OOICCIRRHICHRHCIICOCCCOOHCHHIH` agree:

```
0  invokestatic   locator.IRHOCRROOOIICOOCRRRIRHICOHICOC()   -> root
3  invokevirtual  root.IRHOHHIIHICCIOIIRCCCCCHHIOCCRC()      -> dispatcher
7  invokevirtual  dispatcher.OOOIHHOCHOROCHCRHHROHCRRCICOOH(UUID)
```

### The two injection points

Both take a `PlayerCosmeticsPushV2`; both are called repeatedly by production code and are
safe to call repeatedly (`Map.put` / `Map.compute` overwrite).

```java
dispatcher.CORRIROORHRIRIHCRHROIOCRCCIOIH(push)             // what the websocket calls; writes the equipped list
manager   .RRRRRIRCCIIORHHCCCHICOCRRCOOOH(uuid, push, 0)    // PlayerState: logo/plus colours, HUD refresh
```

The manager handler reads `bridge$getSession()`, returns immediately if null, and otherwise
computes `isSelf`, extracts RGB from `getLogoColor()`/`getPlusColor()`, does
`ROOHCRRCOHIOCHHOHRIIHIHIRIIROO().compute(uuid, lambda)` and finishes with a HUD refresh —
no I/O of any kind.

### Build

```
mod\
  src\rat\cosmetics\RatCosmetics.java     the mod
  stub\net\fabricmc\api\ClientModInitializer.java   compile-only, NOT packaged
  res\fabric.mod.json
```

```powershell
# stub first, into its own directory so it can never reach the output jar
javac -d mod\stubout mod\stub\net\fabricmc\api\ClientModInitializer.java

# the mod, against lunar.jar + the stub
javac -cp "C:\Users\<u>\.lunarclient\offline\multiver\lunar.jar;mod\stubout" `
      -d mod\out mod\src\rat\cosmetics\RatCosmetics.java

# package exactly two entries — the stub's .class must be absent
#   fabric.mod.json
#   rat/cosmetics/RatCosmetics.class
```

`fabric.mod.json` carries no `depends` block on purpose: the loader version is Lunar's own
fork, and pinning it risks the mod silently not loading.

### Deploy — the folder that matters

| path | on the classpath? | evidence |
|---|---|---|
| `profiles\26\mods\` (top level) | **no** | jar placed there alone → `rat-cosmetics.txt` **never created**, entrypoint never ran |
| `profiles\26\mods\fabric-26.3\` | **yes** | jar placed there → file created ≤3 s, `OK` in the log |

Lunar downloads each mod to `mods\` at the path the mrpack declares, then **moves** it into
`mods\fabric-26.3\` — which is where `fabric-api`, `iris`, `modmenu`, `placeholder-api` and
`sodium` all live after a sync. Only that directory reaches the classpath. A stray copy at
the top level is dead weight, and since two jars with the same `id` would be a duplicate-mod
failure, it is left as `rat-cosmetics.jar.disabled` (`.disabled` is the loader's own
recognition suffix).

### Runtime behaviour

A daemon thread named `rat-cosmetics` sleeps 3 s between injections, forever. The period is
deliberate: the AssetServer reconnect loop retries every 30 s, and a successful reconnect
could reset the equipped list, so re-injecting keeps overwriting it. The loop is idempotent
for the same reason the handler is.

Guarding it:

```
NOTREADY root=null                 <- thread woke before the client finished init
NOTREADY mgr=false disp=false      <- root resolved, child services still coming up
OK ids=[3, 2424, 894] uuid=9f8e7d6c-5b4a-4928-9706-f5e4d3c2b1a0
```

`NOTREADY` is timing, not failure — it is written once per distinct message and disappears
as soon as the client is up. `OK` is written only after **both** calls return, and the log
dedupes by message so it never spams.

The UUID is read from `accounts.json` through Gson rather than hard-coded, so changing
`$S2AccountId` does not break the mod — and with `account-manager.ps1` in play it resolves
through `activeAccountLocalId`, falling back to the first entry only when that key is
absent or dangling. A first-match regex would inject cosmetics for whichever account
happens to serialise first, not the one Lunar actually launched. The protobuf builders are
public API and called directly — only the obfuscated Lunar internals go through reflection,
with `getMethod` first and a `getDeclaredMethod` + `setAccessible` walk up the superclass
chain as fallback, since their access flags are not knowable without checking every build.

### Configuration

`%USERPROFILE%\.lunarclient\settings\game\rat-cosmetics.txt`, created on first run with the
defaults — one integer `id` per line, `#` for comments. Change it and restart the game:

```ini
3        <- Lunar Client Classic (cloak)
2424     <- Sun Glasses Black (glasses)
894      <- Blue Tie (bodywear)
```

Log: `%USERPROFILE%\.lunarclient\settings\game\rat-cosmetics.log`.

### Limits

* **Other players' cosmetics do not render.** Their pushes never arrive, and there is no
  offline source for their UUIDs plus equipped lists. Only the local account is injected.
* **Cosmetic textures are not shipped locally.** 0 of the catalog's entries have their
  `.webp` on disk. `jit_index` is an unauthenticated `path sha1 size timestamp` manifest and
  the fetch goes to Lunar's CDN, not through the AssetServer — but it does require network,
  and an id whose asset fails to download renders nothing.
* **The `int` third argument to the manager handler is `0` by guess.** Nothing in the
  bytecode names it. The dispatcher call is the load-bearing one; the manager call supplies
  the colours, and `0` has produced correct logo/plus rendering in testing.
* **Obfuscated names are build-specific.** A new `lunar.jar` needs the three getters and two
  entry points re-mined — `sigs.py` plus a search for the `PlayerCosmeticsPushV2` descriptor
  finds them in seconds.
* Compiles against **JDK 25** (`javac 25.0.4.1`), class file version 69, which the bundled
  Zulu JRE 25 reads natively.
