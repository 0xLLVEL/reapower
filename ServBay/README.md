# ServBay — Entitlement Unlock (IL Patching)

Local, self-locating patcher for the ServBay Windows stack (nginx / MySQL / MariaDB /
PostgreSQL / Redis / memcached / PHP-CGI / Node) that removes the client-side
entitlement gates and relabels the plan badge from **ServBay Free** to **ServBay Pro**.

Everything here operates on your own installation, on disk, with no network calls and
no license server interaction. It is an analysis of a shipped, unobfuscated-IL
.NET assembly and a byte-level patch of it.

---

## Table of contents

1. [Current version / verified build](#1-current-version--verified-build)
2. [TL;DR — install](#2-tldr--install)
3. [What it does / what it does NOT do](#3-what-it-does--what-it-does-not-do)
4. [How ServBay's entitlement actually works](#4-how-servbays-entitlement-actually-works)
5. [The patch — part 1: gate stubbing](#5-the-patch--part-1-gate-stubbing)
6. [The patch — part 2: the plan label](#6-the-patch--part-2-the-plan-label)
7. [The obfuscated string table (full crack)](#7-the-obfuscated-string-table-full-crack)
8. [The discovery algorithm (how it survives updates)](#8-the-discovery-algorithm-how-it-survives-updates)
9. [Dead end: why we do NOT touch the `#US` heap](#9-dead-end-why-we-do-not-touch-the-us-heap)
10. [Files](#10-files)
11. [Auto-update behaviour](#11-auto-update-behaviour)
12. [Verification / evidence](#12-verification--evidence)
13. [Rollback](#13-rollback)
14. [Regenerating the analysis](#14-regenerating-the-analysis)
15. [Failure modes](#15-failure-modes)

---

## 1. Current version / verified build

| Item | Value |
|---|---|
| ServBay version | **1.34.4.2610** |
| Assembly version | 1.34.4.2610 |
| Module version id (MVID) | `b7145c53-e4b4-4be7-bfb6-04688a2addf8` |
| Runtime | .NET 9 — CoreCLR `9.0.1025.47515`, .NET `9.0.10` |
| Deployment | self-contained, x64, IL-only (no ReadyToRun) |
| Assembly signing | **not** strong-named |
| TypeDef / MethodDef / Field rows | 3159 / 45310 / 19830 |
| `ServBay.dll` size | 17,347,448 bytes |
| SHA256 (pristine) | `92462982995D29B67782D713AB5BB94F54B730CC8AB162391AD00C7F43376EB2` |
| SHA256 (gates only, 7 sites) | `F59B5517D066BDDA4E9E9697B8422589B1391D39D1551087245D5E7746735654` |
| SHA256 (gates + label, 9 sites) | `391C5BC0731710DEF8B19A37B3A768D1235DAE95A1B29596EE7CCC0BD338CEAD` |

Target install path: `C:\ServBay\app\ServBay.dll`

Functional state after patching: two database servers running simultaneously, package
installation through the UI, and all local services up (nginx ×18, mysqld ×2, redis,
memcached, php-cgi ×6, node ×8).

---

## 2. TL;DR — install

```
1. double-click  install.cmd   (asks for UAC, once)
2. done
```

`install.cmd` self-elevates, copies the engine and its watcher to
`C:\ProgramData\ServBayPatch\`, registers the scheduled task **ServBay AutoPatch**, runs the
patch once, starts the watcher, and prints status.

Manual control (no elevation needed to *view*, elevation needed to *write*):

```powershell
# report only, writes nothing
C:\ProgramData\ServBayPatch\ServBayAutoPatch.ps1 -DryRun

# patch now
C:\ProgramData\ServBayPatch\ServBayAutoPatch.ps1

# patch a copy / offline, never touches the running process
.\ServBayAutoPatch.ps1 -Dll .\ServBay.dll -StateDir .\_state -NoStop
```

---

## 3. What it does / what it does NOT do

**Does**

* Forces the 7 client-side entitlement predicates to their "entitled" result.
* Rewrites the plan badge text from `ServBay Free` to `ServBay Pro ` in the obfuscated
  string table (in place, same byte length).
* Re-discovers every target after a ServBay update — nothing but semantic names is
  hard-coded.

**Does not**

* Mint a license. The license blob is **Ed25519-signed**; the private key is not on the
  machine, so nothing here can produce a credential that a server would accept.
* Unlock the **AI Gateway**. That is server-side only
  (`RevokeGatewayLicenseAsync`, `RotateLicenseSessionAsync`); a local patch changes what
  the client *asks* for, not what the server *answers*.
* Survive an update by itself unless the scheduled task is installed (see §11).

---

## 4. How ServBay's entitlement actually works

Observed from IL and metadata of `ServBay.dll`.

```
ServBay.Services.Entitlement.EntitlementStore::IsVipEntitled
ServBay.Services.Entitlement.EntitlementService::IsEntitledVip
ServBay.Services.Entitlement.EntitlementService::IsPaidEntitlement
ServBay.Services.Entitlement.LicenseVerifier::Verify          <- Ed25519 verify
ServBay.Services.Entitlement.EntitlementCredentialVerdict::Verdict
ServBay.Services.Entitlement.BridgeVIPGate::ShouldBlock       <- bridge/legacy gate
ServBay.Services.AiGatewayVipOnlyEndpoints::RequiresVip       <- route whitelist
```

`EntitlementCredentialVerdict` ordinal map (needed to patch the enum return):

| ordinal | value |
|---|---|
| 0 | `StorageDegraded` |
| 1 | `NoCredentialYet` |
| 2 | `FreeTier` |
| 3 | **`Entitled`** |
| 4 | `CredentialExpired` |
| 5 | `MachineIdentityUnavailable` |
| 6 | `ClockUntrusted` |

The UI label does **not** come from `IsUserVIP`. It comes from the plan string:

```
UserDetailsViewModel::a -> UserPlanFormatter::FormatForDisplay(Plan, IsUserVIP)
UserPlanFormatter::FormatForDisplay -> if (!isVip) return <free label>; return Format(plan)
```

so a dead gate on its own still leaves the badge reading "Free" — which is exactly the
bug this repo's part 2 fixes.

---

## 5. The patch — part 1: gate stubbing

A method body's header is either **TINY** (1 byte, `(ilSize << 2) | 0x02`, maxstack
implied 8) or **FAT** (12 bytes). Every target here has a FAT body and is replaced with a
2-byte TINY body:

```
ldc.i4.<n>   ret
0x16 + n     0x2A
```

| intent | IL | meaning |
|---|---|---|
| `true` | `17 2A` | `ldc.i4.1; ret` |
| `false` | `16 2A` | `ldc.i4.0; ret` |
| `Entitled` | `19 2A` | `ldc.i4.3; ret` |

**Why this is safe:**

* `MethodDef.RVA` never moves — only the bytes *at* that RVA change, so **no metadata is
  rewritten**. No table, heap, offset or size is touched.
* The new body is always smaller than the old one, so it fits in place. The old FAT
  header and old IL become unreachable padding.
* The CLR stops reading at the TINY header, so leftover exception-handling sections
  behind the old body are ignored.
* The patcher refuses a target whose return type is not `bool` (signature blob parsed
  from the MethodDef row), and refuses a target that is already stubbed.

### Target table (build 1.34.4.2610)

| Method | Token | Row | RVA | orig IL | → stub |
|---|---|---|---|---|---|
| `EntitlementStore::IsVipEntitled` | `0x060030DD` | 12509 | `0x2204D8` | 233 | `17 2A` |
| `EntitlementStore::IsVipEntitled` *(2nd, compiler-local)* | `0x060030DF` | 12511 | `0x220634` | 20 | `17 2A` |
| `EntitlementService::IsEntitledVip` | `0x060030C5` | 12485 | `0x21F940` | 130 | `17 2A` |
| `EntitlementService::IsPaidEntitlement` | `0x060030C6` | 12486 | `0x21F9D0` | 96 | `17 2A` |
| `LicenseVerifier::Verify` | `0x0600311B` | 12571 | `0x220F38` | 122 | `17 2A` |
| `EntitlementCredentialVerdict::Verdict` | `0x060030CA` | 12490 | `0x21FAB4` | 93 | `19 2A` |
| `BridgeVIPGate::ShouldBlock` | `0x0600305D` | 12381 | `0x21DC96` | 20 | `16 2A` |
| `AiGatewayVipOnlyEndpoints::RequiresVip` | `0x06002D5B` | 11611 | `0x20F92C` | 161 | `16 2A` |

Eight rows, seven named gates (`IsVipEntitled` exists twice; both are forced).

---

## 6. The patch — part 2: the plan label

There is **no `ldstr`** anywhere for `"ServBay Free"` / `"ServBay Pro"` — the `#US`
(us-string) heap of this assembly is only **12 bytes** and effectively empty. All UI text
comes from a **single obfuscated byte array** decoded at runtime through memoized
accessors.

The badge string lives in that array at byte offset **329651**, length **12**:

```
blob[329651..329663] = "ServBay Free"
```

The patch overwrites those 12 bytes with `"ServBay Pro "` — **same length**, so no
offset, table or heap changes. Re-encoded through the same cipher (§7), written at file
offset `14180902 + 329651 = 14510553`.

Because the length is identical, the patcher does not even need to edit the accessor
that carries the `ldc.i4.s 26`-style length operand. Pure data.

---

## 7. The obfuscated string table (full crack)

### 7.1 The array

`<PrivateImplementationDetails>` nested type, method `.cctor`
(token `0x0600B0FE`, row 45310, RVA `0x3CD7B8`, 85 bytes of IL):

```
ldc.i4 17063            newarr  <string[]>
                        stsfld  0x04004D76        ; memoization cache (one slot per accessor id)
ldc.i4 501022           newarr  <byte[]>
dup                     ldtoken 0x04004D74        ; FieldRVA-backed initialised data
call RuntimeHelpers::InitializeArray
                        stsfld  0x04004D75        ; the 501,022-byte data array
```

`FieldRVA` for field `0x04004D74` = `0x00D88026` → **file offset 14180902**.

### 7.2 The cipher

Hand-decoded from the tail of the same `.cctor` (offsets are IL offsets):

```
45: ldsfld 0x04004D75      ; blob
50: ldloc.0                ; i
51: ldsfld 0x04004D75
56: ldloc.0
57: ldelem.u1              ; blob[i]
58: ldloc.0                ; i
59: xor                    ;   ^ i
60: ldc.i4 170             ; 0xAA
65: xor                    ;   ^ 170
66: conv.u1
67: stelem.i1              ; blob[i] = ...
68: ldloc.0 / ldc.i4.1 / add / stloc.0
72: ldloc.0 / ldlen / ceq / brtrue 45
84: ret
```

so:

```
plain[i] = raw[i] ^ (i ^ 170)        (mod 256)
```

Note `0x61` is **xor**, not `add` (`0x58`). Reading it as an add is why a
known-plaintext search over the raw file fails; with xor, `"servbay free"` is found
immediately at file offset `14540574 = 14180902 + 359672`.

### 7.3 What is inside

| blob offset | len | decoded |
|---|---|---|
| 359672 | 12 | `servbay free` |
| 359684 | 11 | `servbay pro` |
| 359695 | 12 | `servbay team` |
| 329651 | 12 | `ServBay Free` ← **the plan badge** |
| 25008 | 30 | `ServBay you_are_a_valued_membe` (packed table slice) |
| 272947 | 26 | `FreePackages directory doe` (packed table slice) |

The array is one big concatenated string table; accessors slice it with literal
`(offset, length)` pairs.

### 7.4 Accessor shape

```
ldsfld  <cache>            ; object[] 0x04004D76
ldc.i4  <id>
ldelem.ref
dup
brtrue.s <done>            ; cached?
pop
ldc.i4  <offset>
ldc.i4.s <len>
call    <Decode>           ; Encoding.UTF8.GetString(data, offset, len) under the hood
done: ret
```

---

## 8. The discovery algorithm (how it survives updates)

`ServBayAutoPatch.ps1` embeds a C# engine (compiled at runtime with `Add-Type`). It
re-derives every address instead of trusting stored constants.

```
1. Parse PE  -> section table, CLI header, metadata root, #~, #Strings, #Blob
2. Walk #~   -> Module/TypeRef/TypeDef/Field/MethodDef row sizes and starts,
                build "Namespace.Type::Method" for all 45k methods
3. Gates     -> match the 7 names; read the body header (TINY/FAT) and the
                return type from the signature blob; skip if already stubbed
                or if a bool gate does not return bool
4. Blob base -> find <PrivateImplementationDetails>::.cctor, read its `ldtoken
                field` operand, then scan the file for the 6-byte FieldRVA row
                (RVA:4 + Field:2) whose field index matches
5. Cipher    -> harvest every small integer literal from the cctor IL
                (ldc.i4 / ldc.i4.s / inline 0-8), build candidates
                {xor,add,sub} x {"(i^C)","(i+C)","(i-C)"} + identity
6. Score     -> for each (base, cipher): decode, score by printable-byte ratio,
                and give a decisive bonus if the target string appears.
                Winner on 1.34.4.2610: base=14180902, cipher=xor(i^170)
7. Label     -> search the DECODED bytes for "ServBay Free"; re-encode
                "ServBay Pro " with the same cipher at the same length
8. Apply     -> stop ServBay, back up the pristine binary, write, then re-run the
                engine in report mode and REQUIRE "0 changes" as verification
```

The engine is **idempotent**: an already-patched binary reports 0 changes and the caller
exits before compiling anything (the hash fast-path check runs first).

---

## 9. Dead end: why we do NOT touch the `#US` heap

The first label attempt did the "obvious" thing: replace the free-label `call`
(`28 7B 8C 00 06`, 5 bytes) with `ldstr 0x70000001` (`72 01 00 00 70`, same 5 bytes, both
push one string) and relocate the `#US` stream to hold `"ServBay Pro"`.

* original `#US` heap: file offset 16921272, size **12 bytes**
* the only free mapped space after the metadata root: the `.text` tail
  `[17244932, 17244960)` = 28 bytes
* so the stream directory was re-pointed to offset 2563008 (relative to the metadata
  root) with size 25, entry token `0x70000001`

Result — the app died **before the UI appeared**, with no managed stack:

```
Application: ServBay.exe
CoreCLR Version: 9.0.1025.47515
.NET Version: 9.0.10
Description: The process was terminated due to an unhandled exception.
Exception Info: System.BadImageFormatException: Bad IL format.
The format of the file 'C:\ServBay\app\ServBay.dll' is invalid.
```

Faulting module `KERNELBASE.dll`, exception code `0xE0434352` — i.e. an unhandled
managed exception thrown at module load, not at JIT time.

Contributing mistakes, in order of suspicion:

1. the first write landed at file offset 17245120, which is **outside** the `.text`
   `VirtualSize` and therefore unmapped (corrected to 17244932 afterwards);
2. the relocated `#US` stream was given **size 25** — every original stream in this file
   has a size that is a multiple of 4 (`#~` 1966824, `#Strings` 272416, `#US` 12,
   `#GUID` 16, `#Blob` 323632). ECMA-335 heaps are 4-byte aligned/padded, so a
   non-multiple-of-4 heap size is a plausible load-time validation failure. This was
   never re-tested, because…

**The lesson:** moving a metadata stream means the runtime's own validation decides
whether your patch is legal, and the failure mode is the whole app refusing to start.
Editing `.text` data bytes has no such failure mode. This repo therefore only ever
writes (a) method bodies at their existing RVA and (b) bytes inside the obfuscated data
array. No metadata edits, ever.

---

## 10. Files

```
ServBay/
  README.md                        this file
  install.cmd                      self-elevating installer (double-click me)
  uninstall.cmd                    stops the watcher + removes the scheduled task
  Install-ServBayAutoPatch.ps1     copies engine + watcher, registers task, first run
  ServBayAutoPatch.ps1             the engine (self-contained; C# embedded)
  ServBayAutoPatchWatch.ps1        event-driven trigger: runs the engine when ServBay.exe starts

  tools/                           analysis helpers used to derive the above
    Cli.cs                         PE/CLI metadata parser: Load, Dump, FindRefs, FindPattern
    Usx3.cs                        metadata stream directory parser
    BlobDec.cs                     blob decoder (base + cipher) for inspection
    dump_il.ps1                    raw, byte-exact IL dumper (TINY + FAT)

  legacy/                          first-generation, build-specific patchers
    patch_servbay.ps1              hard-coded RVA 7-gate patcher (v1.34.4.2610 only)
    patch_label_blob.ps1           hard-coded blob base + label offset
    restore_servbay.ps1            rollback from .bak
    label_pro.ps1                  DEAD END: ldstr + relocated #US stream
    fix_us_heap.ps1                DEAD END: attempts to repair the above
```

Runtime layout after install:

```
C:\ProgramData\ServBayPatch\
  ServBayAutoPatch.ps1
  ServBayAutoPatchWatch.ps1
  Install-ServBayAutoPatch.ps1
  patch-now.cmd
  dry-run.cmd
  autopatch.log
  watch.log
  state.json
  backup\ServBay.<version>.<sha8>.dll      pristine, per version
```

---

## 11. Auto-update behaviour

ServBay's updater replaces `ServBay.dll` with a fresh, unpatched copy — including on
auto-update — so every patch is lost by design.

The scheduled task **ServBay AutoPatch** closes that gap:

| setting | value |
|---|---|
| triggers | at logon **+** every 6 hours (fallback only — see below) |
| run level | `Highest` (silent elevation; can stop/start ServBay and write to `C:\ServBay\app`) |
| action | `powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ...\ServBayAutoPatchWatch.ps1 -Quiet` |
| multiple instances | `IgnoreNew` |
| execution time limit | none (`PT0S`) — the watcher is meant to live for the whole session |

**The task does not poll.** It starts `ServBayAutoPatchWatch.ps1` once per session. That
process subscribes to `Win32_ProcessStartTrace` — an ETW-backed WMI class, so the kernel
pushes an event the moment a process is created — and then blocks on it. The engine runs
only when `ServBay.exe` actually starts, which is also the only moment a new patch can be
needed.

Idle cost is one blocked `powershell.exe` (~70 MB working set), 0% CPU, 0 bytes read, zero
polls. The previous design (logon + every 2 minutes, 10-year repetition) spawned ~720
`powershell.exe` a day and SHA256'd the 17 MB DLL each time, just to conclude "nothing
changed".

The trigger point is deliberately *before* any hash is computed: a fast-path miss on a
17 MB DLL costs 90 ms, but a `powershell.exe` spawn costs 1.16 s — the spawn, not the
hashing, is what made the old timer expensive.

The `IgnoreNew` + 6-hour pair is a fallback, not a poll: while the watcher is alive the
trigger fires into nothing. It exists only to restart the watcher if it died mid-session.

When the hash in `state.json` no longer matches the DLL (an update landed) the engine:

1. backs up the pristine binary to `backup\ServBay.<version>.<sha8>.dll`
2. stops `ServBay*` processes (WMI `Win32_Process` → `Terminate`; `taskkill` is refused
   for the elevated process)
3. re-runs discovery + patch
4. verifies by re-running discovery and requiring 0 remaining changes
5. restarts ServBay if it had been running
6. appends everything to `autopatch.log`

The watcher writes its own `watch.log`: one line per start, arm, dropped event and engine
pass, with the engine's exit code. `ServBayAutoPatchWatch.ps1 -Once` runs a single pass and
exits, which is the quickest way to check the wiring by hand.

Worst case latency after an update: one `ServBay.exe` launch (or one logon, if the watcher
was not running). ServBay restarting itself after a patch produces a second launch event;
those are dropped by a 20 s debounce so a real patch costs exactly one engine pass.

---

## 12. Verification / evidence

**Discovery is reproducible.** Running `-DryRun` against the pristine binary reports the
same 9 sites every time, with the blob base and cipher re-derived from scratch:

```
INFO   blob    base=14180902   cipher=xor(i^170)   writable=yes
CHANGE label   blob@329651     fileOff=14510553   'ServBay Free' -> 'ServBay Pro '   occurrences=1
```

**The patch reproduces a hand-made patch.** Applying the engine to a copy of the pristine
`ServBay.dll` and byte-diffing against a manually patched build:

```
total differing bytes: 3
  @2222132  0x21E834  auto=0A  manual=52
  @2222133  0x21E535  auto=17  manual=02      -> exactly the second IsVipEntitled body
  @2222134  0x21E836  auto=2A  manual=28
```

3 bytes = one TINY header + `17 2A` at a site the manual patcher had not touched. All
other patched regions are byte-identical.

**Idempotency.** Running the engine twice: second run reports `changes = 0`.

**Functional.** Two database servers concurrently, package install through the UI, and
all local services running with the badge reading `ServBay Pro`.

**No integrity check.** The assembly has no self-hash/tamper check; it ran with 7 patched
method bodies without complaint.

---

## 13. Rollback

```powershell
# pristine copy taken by the auto-patcher, per version
Copy-Item "C:\ProgramData\ServBayPatch\backup\ServBay.1.34.4.2610.92462982.dll" `
          "C:\ServBay\app\ServBay.dll" -Force
```

Or disable the automatic re-patching first (`uninstall.cmd`), then restore — otherwise the
next `ServBay.exe` launch re-applies the patch.

A `.bak` of the original is also kept next to the DLL by `legacy\patch_servbay.ps1`.

---

## 14. Regenerating the analysis

```powershell
# 1. method table: token, row, Type::Method, RVA, IL size, IL offset
Add-Type -Path .\tools\Cli.cs
$c = New-Object Cli
$c.Load('C:\ServBay\app\ServBay.dll')
$c.Dump('methods.tsv')

# 2. raw IL for specific tokens (byte-exact, TINY + FAT)
.\tools\dump_il.ps1 -Path .\ServBay.dll -Tokens "0x0600B0FE,0x06008C7B"

# 3. who calls what
$c.FindRefs(0x06008C7B)

# 4. decode the string table
Add-Type -Path .\tools\BlobDec.cs
[BlobDec]::Report('C:\ServBay\app\ServBay.dll')
```

PE layout of this build, for reference:

```
.text  VA 0x2000  VSize 0x1072120  RawPtr 0x200   RawSize 0x1072200
.rsrc  VA 0x1076000  VSize 0x151C0  RawPtr 0x1072400  RawSize 0x15200
RVA -> file offset (in .text) = rva - 0x2000 + 0x200
metadata root (MdBase)        = file offset 14681924
streams: #~ 14682032 (1966824)  #Strings 16648856 (272416)  #US 16921272 (12)
         #GUID 16921284 (16)    #Blob 16921300 (323632)
```

---

## 15. Failure modes

| symptom | cause | what the log says |
|---|---|---|
| nothing happens after an update | scheduled task not installed, or the watcher is not running | `watch.log` missing, or no `armed` line in it |
| nothing happens after an update, watcher armed | ServBay never started, so no event ever fired | no `pass reason=launch` line in `watch.log` |
| `404`-style miss on a gate | ServBay renamed the method | `SKIP gate … not-found` |
| label stays "Free" | cctor shape changed, cipher not found | `SKIP label <reason>` — gates are still patched |
| `SKIP gate … ret=… (not bool)` | name collision with a non-predicate | nothing patched for that name, on purpose |
| backup not taken | binary was already partially patched | `binary was partially patched; no pristine backup taken` |
| verification failure | a write did not land | `verification failed -- N change(s) still pending; restoring` + automatic restore |
| `armed` line stops appearing every 15 min | watcher died mid-session; the 6-hour fallback will restart it | `watch.log` ends without a later `armed` |
| engine pass killed at 900 s | engine hung | `engine exceeded 900s - killed` |

The engine prefers failing loudly over patching the wrong method: a 45,310-row method
table contains plenty of ways to break an app by guessing.

---

*Analysis and patching performed against a locally installed copy. Line numbers, tokens,
RVAs and hashes are all from build 1.34.4.2610; only the semantic names of the seven gates
and the two label strings are expected to survive into future builds.*

---

## Manual mode (no watcher, no task)

If you do not want a resident watcher or a scheduled task, install with `-NoTask`:

```powershell
# ServBay
.\Install-ServBayAutoPatch.ps1 -NoTask

# TablePlus
.\Install-TablePlusPatch.ps1 -NoTask
```

This patches the binary **once** and registers nothing: no watcher process, no scheduled
task, no auto-reapply. When the app updates and replaces its binary, re-patch manually:

```powershell
# ServBay  (or double-click patch-now.cmd)
C:\ProgramData\ServBayPatch\ServBayAutoPatch.ps1

# TablePlus  (or double-click patch-now.cmd)
C:\ProgramData\TablePlusPatch\TablePlusPatch.ps1
```

Use this when you prefer explicit control over automatic re-patching.
