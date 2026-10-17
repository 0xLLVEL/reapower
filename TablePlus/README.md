# TablePlus — License Gate Unlock (IL Patching)

Local, version-tolerant patcher for the TablePlus database client (MySQL / PostgreSQL /
SQLite / Redis / MongoDB / SQL Server …) that removes the two client-side license gates
so the app runs as licensed with no expiry.

Everything here operates on your own installation, on disk, with no network calls and no
license server interaction. It is an analysis of a shipped, managed .NET assembly and a
byte-level patch of it: **18 bytes of 156,425,792**.

---

## Table of contents

1. [Current version / verified build](#1-current-version--verified-build)
2. [TL;DR — install](#2-tldr--install)
3. [What it does / what it does NOT do](#3-what-it-does--what-it-does-not-do)
4. [How TablePlus's licensing actually works](#4-how-tablepluss-licensing-actually-works)
5. [The patch — part 1: `IsLicensed`](#5-the-patch--part-1-islicensed)
6. [The patch — part 2: `get_DayBeforeExpiration`](#6-the-patch--part-2-get_daybeforeexpiration)
7. [The matcher (how it survives updates)](#7-the-matcher-how-it-survives-updates)
8. [Analysing a 156 MB assembly](#8-analysing-a-156-mb-assembly)
9. [Files](#9-files)
10. [Auto-update behaviour](#10-auto-update-behaviour)
11. [Verification / evidence](#11-verification--evidence)
12. [Rollback](#12-rollback)
13. [Regenerating the analysis](#13-regenerating-the-analysis)
14. [Failure modes](#14-failure-modes)
15. [Limits](#15-limits)

---

## 1. Current version / verified build

| Item | Value |
|---|---|
| TablePlus build | **26.10.16** |
| PE timestamp | `0x6AA7BB46` — 2026-09-14 09:15:50Z |
| Module version id (MVID) | `07fa9fdd-79fa-425f-8f64-13c9447eac5b` |
| Runtime | .NET Framework 4.8.1 (WPF) — `TablePlus.exe.config` |
| Format | PE32+, x86_64, **managed**, entry `0x060039E2`, `SizeOfImage 0x09530000` |
| CLI header flags | `0x00000001` — `ILONLY` set, `STRONGNAMESIGNED` clear |
| Assembly signing | **not** strong-named (strong-name directory RVA `0x0`, size `0` — nothing to invalidate) |
| TypeDef / MethodDef rows | 4,607 / **40,072** |
| `TablePlus.exe` size | 156,425,792 bytes |
| SHA-256 (pristine) | `03A5BAD42EC539630E9B293409BCF7ABCF993CAC85EBF28C64120C0576A37A24` |
| SHA-256 (patched) | `9F4F5788C18264BEF75F35FC2FC3E60D404EB2171B96AEC6BA4603A4464B11D4` |
| Bytes changed | **18** |

Target install path: `C:\Program Files\TablePlus\TablePlus.exe`

---

## 2. TL;DR — install

```
1. double-click  install.cmd   (asks for UAC, once)
2. done
```

`install.cmd` self-elevates, copies the engine and its watcher to
`C:\ProgramData\TablePlusPatch\`, patches the exe that is installed right now, registers
the scheduled task **TablePlus License Patch**, starts the watcher, and prints status.

Manual control (no elevation needed to *view*, elevation needed to *write*):

```powershell
# report only, writes nothing
C:\ProgramData\TablePlusPatch\TablePlusPatch.ps1 -DryRun

# patch now
C:\ProgramData\TablePlusPatch\TablePlusPatch.ps1

# restore the original exe
C:\ProgramData\TablePlusPatch\TablePlusPatch.ps1 -Restore
```

---

## 3. What it does / what it does NOT do

**Does**

* Forces `TablePlus.Source.Service.LicenseService::IsLicensed` to `true` — the single
  predicate read from **17 call sites**.
* Forces `LicenseService::get_DayBeforeExpiration` to `9999` — the "updates expire in N
  days" value the workspace window reads to decide whether to show the trial button.
* Re-discovers both sites by **method name after a TablePlus update** — nothing but
  semantic names, opcode shapes and IL hashes is hard-coded. No RVA is ever trusted.

**Does not**

* Touch the metadata tables. No table, heap, stream offset or size is rewritten — only
  the bytes *inside* two method bodies at their existing `MethodDef.RVA`.
* Fake an online activation. If TablePlus verifies a license against its server
  (`SourceService::CheckLicenseOnline`, `RegisterLicense`, `UnregisterLicense`) that
  network exchange is left exactly as it is; only the local gate is removed.
* Survive an update by itself unless the scheduled task is installed (see §10).

---

## 4. How TablePlus's licensing actually works

Observed from the IL and metadata of `TablePlus.exe`. All of it lives in namespace
`TablePlus.Source`; typedef `LicenseService` = `0x02000633`.

| Field | Token | Note |
|---|---|---|
| `isValidLicense` | `0x040013F6` | bool, private — the single source of truth |
| `license` | `0x040013F7` | instance of `TablePlus.Source.Models.License` |
| `IsExpireChecked` | `0x040013F8` | public bool |

| Method | Token | Original IL (pristine build) | Role |
|---|---|---|---|
| `IsLicensed` | `0x06003E08` | `02 7B F6 13 00 04 2A` | the single predicate |
| `get_DayBeforeExpiration` | `0x06003E06` | `02 7B F7 13 00 04 6F 35 43 00 06 2A` | days left before updates expire |
| `Check` | `0x06003E0E` | 108 B, FAT | loads the license JSON, checks the device ID ("Invalid ID") → sets `isValidLicense` |
| `Remove` | `0x06003E0D` | 61 B, FAT | removes the stored key, `isValidLicense = false` |
| `GetSign` / `GetEmail` / `UpdateAvailableUtils` | `…E09` / `…E0A` / `…E0B` | 31 B | read `license.X ?? ""` |
| `Identifier` / `BaseId` / `BiosId` / `GetMacAdress` | — | — | machine fingerprint (WMI `Win32_BaseBoard`, `Win32_BIOS`) |

Disassembly of the two targets, straight from `tp_methods.tsv` (rows read from the
**pristine** build, so `ilSize` is the pre-patch size):

| Token | Row | Type::Method | RVA | ilSize | ilOffset |
|---|---|---|---|---|---|
| `0x06003E06` | 15878 | `TablePlus.Source.Service.LicenseService::get_DayBeforeExpiration` | `0xF8675` | 12 | `0xF6876` |
| `0x06003E08` | 15880 | `TablePlus.Source.Service.LicenseService::IsLicensed` | `0xF8690` | 7 | `0xF6891` |
| `0x06004335` | 17205 | `TablePlus.Source.Models.License::get_DayBeforeExpiration` | `0x1121953` | 7 | `0x1114274` |
| `0x060056EA` | 22250 | `TablePlus.Source.Windows.Workspace.WorkspaceWindow::UpdatePropertiesBasedOnLicense` | `0x1602652` | 65 | `0x1594984` |

That third row is the model getter the service getter used to call (`6F 35 43 00 06` =
`callvirt 0x06004335`), which is why the service getter is only 12 bytes: it forwards,
it does not compute.

The `TablePlus.Source.Models.License` model (`0x020006A5`) stores the license as JSON
with four keys — `deviceID`, `updatesAvailableUntil`, `email`, `sign`
(`Load` `0x06004342`, `Save` `0x06004343`, `IsInitialized` `0x06004340`).

### Why one predicate is enough

`IsLicensed` has **17 callers**:

```
MainWindow::ReloadLicense / RegisterLicense
Source.Windows.Register.LicenseWindow::UnregisterDevice
Source.Windows.Register.RegisterWindow::ActivateHandler
Source.Windows.Workspace.OpenWorkspaceWindow::OpenConnection
Source.Windows.Workspace.WorkspaceWindow::AddConnection
                                        ::TryAddPreloadedConnection
                                        ::ShowMetricsBoardIfNeeded
                                        ::ShowDiagramBoardIfNeeded
                                        ::MoveWorkspaceToNewWindow
                                        ::UpdatePropertiesBasedOnLicense
                                        ::LicenseWarningClicked
                                        ::UpdatePropertiesBasedOnLicense (<b__>)
ContentController::AddItemTab / OpenItemOverview
WorkspaceController::RegisterLicense
TableDataController::AdvancedFilterValidate
<OpenConnections>d__41::MoveNext
```

### Why the second gate is needed too

The badge is not driven by `IsLicensed` alone. `WorkspaceWindow::UpdatePropertiesBasedOnLicense`
(`0x060056EA`):

```
if (!IsLicensed)                   -> ShowTrialButton          (0x060056EB)
else if (DayBeforeExpiration >= 0) -> HideTrialButton          (0x060056EC)
else if (Setting.X)                -> HideTrialButton
else                               -> ShowTrialButton
```

So the "licensed and not expired" state requires `IsLicensed == true` **and**
`DayBeforeExpiration >= 0`. That is why there are two gates, not one — the same class of
bug ServBay had with its plan badge.

---

## 5. The patch — part 1: `IsLicensed`

A method body header is either **TINY** (1 byte, `(ilSize << 2) | 0x02`, maxstack implied
8) or **FAT** (12 bytes). Both targets here have TINY bodies, and both replacements are
smaller than the original, so they fit in place:

| | |
|---|---|
| RVA | `0x000F8690` |
| Header (file offset) | `0xF6890` = `0x1E` → TINY, ilSize 7 |
| IL (file offset) | `0xF6891` |
| Before | `02 7B F6 13 00 04 2A` → `ldarg.0; ldfld isValidLicense; ret` |
| After | `17 2A` → `ldc.i4.1; ret` |

```
0xF6890:  1E 02 7B F6 13 00 04 2A     ->  0A 17 2A 00 00 00 00 00
```

The 5 surplus bytes are zero-filled, the header becomes `0x0A` (TINY, ilSize 2), and
`MethodDef.RVA` never moves.

---

## 6. The patch — part 2: `get_DayBeforeExpiration`

| | |
|---|---|
| RVA | `0x000F8675` |
| Header (file offset) | `0xF6875` = `0x32` → TINY, ilSize 12 |
| IL (file offset) | `0xF6876` |
| Before | `02 7B F7 13 00 04 6F 35 43 00 06 2A` → `ldarg.0; ldfld license (0x040013F7); callvirt 0x06004335 (Models.License::get_DayBeforeExpiration); ret` |
| After | `20 0F 27 00 00 2A` → `ldc.i4 9999; ret` |

```
0xF6875:  32 02 7B F7 13 00 04 6F 35 43 00 06 2A  ->  1A 20 0F 27 00 00 2A 00 00 00 00 00 00
```

The original body forwarded to the license model; the replacement returns the constant
`9999`. Header `0x1A` = TINY, ilSize 6; the 6 surplus bytes are zero-filled. The model
getter (`0x06004335`) is deliberately left pristine — only the service-level gate is cut,
which keeps the change surface at two bodies.

Both sites together:

```
total differing bytes: 18
  @0xF6875   0xF6875..0xF6881   get_DayBeforeExpiration body   (13 bytes -> 6)
  @0xF6890   0xF6890..0xF6897   IsLicensed body                ( 8 bytes -> 2)
```

Nothing outside those two runs is touched — see §11 for the full byte list.

---

## 7. The matcher (how it survives updates)

`TablePlusPatch.ps1` never stores an offset. Per site, in order:

| # | Condition | Action | Tier |
|---|---|---|---|
| 1 | `FindRow(fullName)` hits the metadata name table | patch | `exact` |
| 2 | SHA-256 of current IL == known patched value | skip (idempotent) | — |
| 3 | SHA-256 of current IL == known pristine value | patch | `exact` |
| 4 | IL differs, but the **opcode skeleton** still matches | patch | `shape` |
| 5 | Declaring type gone: same short name under any type, shape matches | patch | `fuzzy` |
| 6 | Shape differs too | **refuse**, record, notify once | `dark` |

The shape is a skeleton of the IL with every operand masked to `-1` (wildcard):

```powershell
# IsLicensed — ldarg.0; ldfld <any>; ret
Shapes        = @(, [int[]](0x02, 0x7B, -1, -1, -1, -1, 0x2A))
PatchedShapes = @(, [int[]](0x17, 0x2A))
```

So if TablePlus is recompiled and the field token of `isValidLicense` shifts (which moves
the four bytes after `7B`), tier 4 still recognises the method. If the declaring type is
renamed, `FindRowsByName` collects every `IsLicensed`-shaped method in the assembly,
prefers the one in `TablePlus.Source.Service.`, and patches it — tier `fuzzy`.

**A `dark` site is never patched blind.** The engine would rather let TablePlus return to
free mode than corrupt the exe. When a gate is rewritten into an unrecognisable shape the
engine leaves it alone, writes the fact to `tableplus-patch.log`, and shows one
MessageBox per build (deduped through `state.json`, capped at 50 entries, so it does not
nag on every launch).

### Idempotency and the fast path

Before anything else, the file's SHA-256 is compared against `lastGood` in
`state.json`. Equal → exit immediately: no 156 MB metadata parse, no waiting for a
running `TablePlus` process. A pass with nothing to do costs one hash — and a pass now
only happens when TablePlus is actually opened.

---

## 8. Analysing a 156 MB assembly

Executable IL ends around file offset 44 MB; the remaining ≈110 MB is
`ManifestResource`. REA's static analysis cannot consume a file this size:

| REA limit | value |
|---|---|
| `max_snapshot_bytes` | 134,217,728 (128 MiB) |
| `max_file_bytes` (pe_resources) | 67,108,864 (64 MiB) |

So analysis runs against a **derived artifact** built by `tools/make_rea_artifact.ps1`: a
**byte-identical 48 MiB prefix** of the original with only the PE header adjusted so it
stays well-formed —

* `NumberOfSections` reduced to 1, the second section entry cleared
* `.text` `VirtualSize` / `SizeOfRawData` clamped to the kept length
* data directories and CLI header directories that point past the kept region cleared

Metadata and IL bytes are **not** changed at any offset, so every coordinate in this
document refers to the **original** file.

The build is deterministic — rebuilding from the pristine binary reproduces the exact
artifact that was analysed:

```
.\tools\make_rea_artifact.ps1 -Source .\TablePlus.exe.orig -Out .\TablePlus.rea.exe
  REA artifact: TablePlus.rea.exe  (50,331,648 bytes, byte-identical prefix of the source)
  SHA256     : E17FC7C265B911C58F2338AC98030978F4AFAE79CE57F426EF0B2116A6700BB6
```

The script refuses a source with no CLI header inside the kept range (a native binary, or
a `-Keep` smaller than the metadata) instead of emitting a malformed file.

> Limitation: on the derived artifact REA reports member `rva` / `file_offset` with a
> fixed shift of ≈54 bytes. Method identity is still sound because the `il_sha256` REA
> reports matches the IL at the offsets this patch uses **byte-for-byte** (verified for 8
> methods). The canonical coordinates here come from reading the metadata tables directly.

---

## 9. Files

```
TablePlus/
  README.md                        this file
  install.cmd                      self-elevating installer (double-click me)
  uninstall.cmd                    stops the watcher, removes the task, restores the exe
  Install-TablePlusPatch.ps1       copies engine + watcher, registers task, first run
  TablePlusPatch.ps1               the engine (find-by-name, SHA verify, in-place write)
  TablePlusPatchWatch.ps1          event-driven trigger: runs the engine when TablePlus.exe starts
  TPCli.cs                         PE + CLI metadata reader and TINY-IL writer
                                   (runtime dependency of the engine — stays at top level)

  tools/                           analysis helpers used to derive the above
    Pe.cs                          PE header / section / data-directory dump, byte search
    dump_il.ps1                    raw, byte-exact IL dumper (TINY + FAT)
    make_rea_artifact.ps1          builds the <64 MiB derived artifact for REA
    byte_diff.ps1                  enumerates every differing byte between two builds
```

Runtime layout after install:

```
C:\ProgramData\TablePlusPatch\
  TablePlusPatch.ps1
  TablePlusPatchWatch.ps1
  TPCli.cs
  tableplus-patch.log
  watch.log                        one line per arm, dropped event and engine pass
  versions.txt                     one line per vendor build seen (date, sha, size)
  state.json                       { lastGood, warned[], when }
  backup\TablePlus.exe.orig        pristine, refreshed per vendor build
```

`tp_methods.tsv` (40,072 rows: token, row, `Type::Method`, RVA, ilSize, ilOffset) is
generated on demand — it is 3.7 MB and is not committed.

---

## 10. Auto-update behaviour

TablePlus updates through **WinSparkle** (`x64\WinSparkle.dll`); an update overwrites
`TablePlus.exe` wholesale and the patch is gone by design.

The scheduled task **TablePlus License Patch** closes that gap:

| setting | value |
|---|---|
| triggers | at logon **+** every 6 hours (fallback only — see below) |
| run level | `Highest` (silent elevation; can write to `C:\Program Files\TablePlus`) |
| action | `powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ...\TablePlusPatchWatch.ps1 -Quiet` |
| multiple instances | `IgnoreNew` |
| execution time limit | none (`PT0S`) — the watcher is meant to live for the whole session |
| principal | interactive user, `RunLevel Highest` |

**The task does not poll.** It starts `TablePlusPatchWatch.ps1` once per session. That
process subscribes to `Win32_ProcessStartTrace` — an ETW-backed WMI class, so the kernel
pushes an event the moment a process is created — and then blocks on it. The engine runs
only when `TablePlus.exe` actually starts.

Idle cost is one blocked `powershell.exe` (~70 MB working set), 0% CPU, 0 bytes read, zero
polls. The previous design (logon + every 10 minutes) spawned ~144 `powershell.exe` a day
and SHA256'd the 149 MB exe each time — roughly 21 GB read per day — to conclude "nothing
changed". A `powershell.exe` spawn costs 1.16 s, a warm SHA256 of the exe 729 ms; the spawn
was the bigger half, so the spawn is what had to go.

The `IgnoreNew` + 6-hour pair is a fallback, not a poll: while the watcher is alive the
trigger fires into nothing. It exists only to restart the watcher if it died mid-session.

When it does need to act, it:

1. refreshes `backup\TablePlus.exe.orig` **only if the file on disk is still a vendor
   build** (at least one site was pristine) and appends to `versions.txt`
2. patches both sites, writing the new IL in place and zero-filling the surplus bytes
3. moves the patched copy over the target atomically (write `.tp-new`, then `Move-Item -Force`)
4. records `lastGood` in `state.json` and appends a line to `tableplus-patch.log`

### Why the launch trigger still catches a blocked patch

TablePlus holds its own exe open, so a patch cannot land while it is running. The old
10-minute poll worked around that by retrying forever; a naive launch trigger would fire
once, fail, and give up until the *next* launch.

The watcher therefore treats exit code `3` (`target is still locked`) as a *pending* state.
It wakes every 60 s and retries until the patch lands — which is normally the moment you
close TablePlus. A session with nothing pending never wakes, and `-WaitForExitSeconds` is
deliberately not passed to the engine: fail fast and let the watcher own the cadence rather
than blocking a child process for 120 s on every attempt.

Worst case latency after an update: one `TablePlus.exe` launch plus however long you keep
it open, one silent write.

The backup is **version-aware**: because `.orig` is only refreshed from a vendor build,
it always holds the pristine copy of the build actually installed — never an older one.

---

## 11. Verification / evidence

**The patch is exactly 18 bytes.** `tools/byte_diff.ps1` over
`backup\TablePlus.exe.orig` vs the live exe:

```
A (original) = 03A5BAD42EC539630E9B293409BCF7ABCF993CAC85EBF28C64120C0576A37A24
B (patched)  = 9F4F5788C18264BEF75F35FC2FC3E60D404EB2171B96AEC6BA4603A4464B11D4
total differing bytes: 18
  @0xF6875  orig=32  patched=1A     <- new TINY header, ilSize 6
  @0xF6876  orig=02  patched=20
  @0xF6877  orig=7B  patched=0F
  @0xF6878  orig=F7  patched=27
  @0xF6879  orig=13  patched=00
  @0xF687B  orig=04  patched=2A
  @0xF687C  orig=6F  patched=00
  @0xF687D  orig=35  patched=00
  @0xF687E  orig=43  patched=00
  @0xF6880  orig=06  patched=00
  @0xF6881  orig=2A  patched=00
  @0xF6890  orig=1E  patched=0A     <- new TINY header, ilSize 2
  @0xF6891  orig=02  patched=17
  @0xF6892  orig=7B  patched=2A
  @0xF6893  orig=F6  patched=00
  @0xF6894  orig=13  patched=00
  @0xF6896  orig=04  patched=00
  @0xF6897  orig=2A  patched=00
```

Note the two untouched bytes at `0xF687A` and `0xF6895`: the original IL had two `00`
bytes there already, so they do not appear in the diff. 18 changed bytes = 11 in the
first body + 7 in the second.

**Discovery quotes.** `-DryRun` against the live binary:

```
TablePlus license gate patch
  target : C:\Program Files\TablePlus\TablePlus.exe
  size   : 156,425,792 bytes
  method : 40,072
  sha256 : 9F4F5788C18264BEF75F35FC2FC3E60D404EB2171B96AEC6BA4603A4464B11D4

  TablePlus.Source.Service.LicenseService::IsLicensed
      rva 0x000F8690  body 0xF6890  il@0xF6891  ilSize 2
      current IL  : 172A
      already patched (hash) - skipped
  TablePlus.Source.Service.LicenseService::get_DayBeforeExpiration
      rva 0x000F8675  body 0xF6875  il@0xF6876  ilSize 6
      current IL  : 200F2700002A
      already patched (hash) - skipped

  DRY RUN: 0 to patch, 2 already patched, 0 unknown
```

**Re-read by REA** from the patched binary — the patched methods decompile to a constant
return, and the neighbours are untouched:

```
0x06003e08  IsLicensed  ->bool  il=2  hdr=tiny  ops: ldc.i4.1x1 retx1
0x06003e06  get_DayBeforeExpiration ->i4  il=6  hdr=tiny  ops: ldc.i4x1 retx1
                                      anchors: 0:ldc.i4(9999)
0x06003e0d  Remove      ->void  il=61   (unchanged, same il_sha256)
0x06003e0e  Check       ->void  il=108  (unchanged, same il_sha256)
```

`Check`, `Remove`, `GetSign`, `GetEmail` and `UpdateAvailableUtils` are deliberately left
pristine, which is what makes the re-read a usable check: their `il_sha256` must equal the
values recorded from the original build.

**Idempotency.** Running the engine twice: the second run reports `changes = 0` and takes
the fast path.

**The matcher was proven against four simulated updates**:

```
normal update                      -> exact  : 2 patched
recompile, field token shifted     -> shape  : 2 patched   (the previous engine: 1, the other went silently dark)
gate rewritten                     -> dark   : 0 patched, one notification, next run silent
declaring type renamed             -> fuzzy  : 2 patched
```

**REA evidence:**

| Artifact | SHA-256 | Evidence |
|---|---|---|
| `TablePlus.rea.exe` (48 MiB prefix of the original) | `e17fc7c265b911c58f2338ac98030978f4afae79ce57f426ef0b2116a6700bb6` | artifact `ev_3f78cbf7…`, members `ev_a40adb67…`, methods `ev_376d8faa…` |
| `TablePlus.patched.rea.exe` | `9228cb2407e7da723bda470e60e6eb2491149bb607b0dde51bb0b63f069a4405` | members `ev_57b9193e…` |

**Regeneration is exact.** The artifact hash above is not a note, it is reproducible:
rebuilding it from the pristine exe with `tools/make_rea_artifact.ps1` yields
`E17FC7C2…00BB6` byte-for-byte (see §8). Re-running the engine on a fresh pristine copy
yields `9F4F5788…B11D4`, and `tools/byte_diff.ps1` then reports exactly the 18 offsets
listed above — so the published SHA-256 of the patched binary is a property of the patch,
not of this machine.

---

## 12. Rollback

```powershell
# stop the automatic re-patching first, otherwise the next TablePlus launch re-applies it
.\uninstall.cmd

# then restore by hand if needed
Copy-Item "C:\ProgramData\TablePlusPatch\backup\TablePlus.exe.orig" `
          "C:\Program Files\TablePlus\TablePlus.exe" -Force
```

Or in one step, without removing the task:

```powershell
C:\ProgramData\TablePlusPatch\TablePlusPatch.ps1 -Restore
```

`-Restore` prefers `TablePlus.exe.bak` next to the exe and falls back to
`backup\TablePlus.exe.orig`. It refuses to run while a `TablePlus` process is alive
(exit 3) — the file is locked.

---

## 13. Regenerating the analysis

```powershell
# 1. method table: token, row, Type::Method, RVA, ilSize, ilOffset
Add-Type -Path .\TPCli.cs
$cli = New-Object TPCli
$cli.Load('C:\Program Files\TablePlus\TablePlus.exe')
$cli.Lines | Set-Content tp_methods.tsv      # 40,072 rows

# 2. raw IL for specific tokens (byte-exact, TINY + FAT, ldstr decoded from #US)
.\tools\dump_il.ps1 -Path .\TablePlus.exe -Tokens "0x06003e08,0x06003e06,0x060056ea"

# 3. PE header / sections / data directories
Add-Type -Path .\tools\Pe.cs
$p = New-Object Pe; $p.Load('.\TablePlus.exe'); $p.Parse(); $p.Report()

# 4. build the REA-consumable artifact (<64 MiB), then analyse it
.\tools\make_rea_artifact.ps1 -Source .\TablePlus.exe -Out .\TablePlus.rea.exe

# 5. prove a patch is N bytes and nothing else
.\tools\byte_diff.ps1 -A .\TablePlus.exe.orig -B .\TablePlus.exe
```

PE layout of this build, for reference:

```
Machine 0x8664 (x64)   PE32+   Sections 2   SizeOfImage 0x09530000
.text   VA 0x00002000    VSize 0x094E4D60   RawPtr 0x00000200   RawSize 0x094E4E00
.rsrc   VA 0x094E8000    VSize 0x00046E00   RawPtr 0x094E5000   RawSize 0x00046E00

RVA -> file offset (in .text) = rva - 0x2000 + 0x200
CLI header      rva 0x00002000  size 0x48      -> file 0x200
Metadata root   rva 0x002DB5B8  size 0x399AFC  -> file 0x2D97B8  (MdBase)

streams (#~ dir, relative to MdBase, all sizes a multiple of 4)
  #~        file  2988068   size 2233464
  #Strings  file  5221532   size  669824
  #US       file  5891356   size  521408
  #GUID     file  6412764   size      16
  #Blob     file  6412780   size  350408
```

---

## 14. Failure modes

| symptom | cause | what it says |
|---|---|---|
| patch reverts after an update | scheduled task not installed, or the watcher is not running | `watch.log` missing, or no `armed` line in it |
| patch reverts after an update, watcher armed | the patch is pending because TablePlus stayed open | `patch pending - target still locked, retrying every 60s` |
| pass runs but writes nothing | file already clean | `already clean (fast path, sha …) - done` |
| one gate patched, one not | the other gate was rewritten | `unknown IL (shape differs too) - NOT touched` |
| exit `3` | `TablePlus` still running, file locked → the watcher keeps retrying | `TablePlus is still running - file is locked.` |
| exit `4` + one MessageBox | gate unrecognisable → dark | `nothing patchable, N dark site(s)` |
| repeated notifications | — | deduped per site label in `state.json` |
| exit `5` | body too small for the replacement | `FAILED to patch <site>` |
| exit `2` | target missing | `target not found: <path>` |
| no backup taken | file was already partially patched | the `.orig` refresh is skipped on purpose |
| `armed` line stops appearing every 15 min | watcher died mid-session; the 6-hour fallback will restart it | `watch.log` ends without a later `armed` |
| engine pass killed at 900 s | engine hung | `engine exceeded 900s - killed` |

The engine prefers failing loudly over patching the wrong method: a 40,072-row method
table contains plenty of ways to break an app by guessing.

---

## 15. Limits

* This patch touches the **client gate**. Server-side license verification for
  activation/registration (`CheckLicenseOnline`, `RegisterLicense`, `UnregisterLicense`)
  is left intact — the network exchange still happens, only the local gate is removed.
* Not yet exercised against a live GUI session long enough to watch the trial button
  across an expiry boundary; the IL-level read (`IsLicensed == true` and
  `DayBeforeExpiration == 9999`) is what both call sites consume.
* `TablePlus.exe` and any other vendor binary are **not** in this repository.

---

*Analysis and patching performed against a locally installed copy. Offsets, tokens, RVAs
and hashes are all from build 26.10.16; only the two method names, their opcode shapes and
the `TablePlus.Source.Service` namespace are expected to survive into future builds.*
