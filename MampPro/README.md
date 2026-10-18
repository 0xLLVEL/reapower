# MAMP PRO — License Gate Unlock (IL Patching)

Local, version-tolerant patcher for MAMP PRO (Windows local dev stack) that removes the
client-side license gates: no trial countdown, no serial dialog, no expiry nags — the app
starts as if licensed.

Everything here operates on your own installation, on disk, with no network calls and no
license server interaction. It is an analysis of a shipped, managed .NET 6 assembly and a
byte-level patch of it: **1,353 bytes of 2,031,616**, and every one of those bytes sits
inside four method bodies.

---

## Table of contents

1. [Current version / verified build](#1-current-version--verified-build)
2. [TL;DR — install](#2-tldr--install)
3. [What it does / what it does NOT do](#3-what-it-does--what-it-does-not-do)
4. [How MAMP PRO's licensing actually works](#4-how-mamp-pros-licensing-actually-works)
5. [The four patches](#5-the-four-patches)
6. [FAT method bodies: how the rewrite stays load-safe](#6-fat-method-bodies-how-the-rewrite-stays-load-safe)
7. [The matcher (how it survives updates)](#7-the-matcher-how-it-survives-updates)
8. [The module-wide ctor gate](#8-the-module-wide-ctor-gate)
9. [Why in-place instead of a rewriter](#9-why-in-place-instead-of-a-rewriter)
10. [Files](#10-files)
11. [Manual mode](#11-manual-mode)
12. [Verification / evidence](#12-verification--evidence)
13. [Rollback](#13-rollback)
14. [Regenerating the analysis](#14-regenerating-the-analysis)
15. [Failure modes](#15-failure-modes)
16. [Limits](#16-limits)

---

## 1. Current version / verified build

| Item | Value |
|---|---|
| MAMP PRO build | **5.0.6.7029** |
| Assembly | `C:\MAMPPRO\net\MAMPPRO.dll` — 2,031,616 bytes |
| Runtime | .NET 6 (CoreCLR 6.0.522), WPF |
| CLI header flags | `0x00000003` — `ILONLY` + `32BITREQUIRED`, not R2R |
| Assembly signing | **not** strong-named — in-place body patches load as-is |
| COFF timestamp | `0xF452B02B` — deterministic-build randomization |
| TypeDef / MethodDef rows | 5,490 methods |
| `.text` section | VA `0x2000`, VSize `0x1C4340`, RawPtr `0x200` |
| SHA-256 (pristine) | `332819BB1F0B552EA4FD49A3AC994E396A2677D7D1996AFF66C540D0093980E8` |
| SHA-256 (patched) | `913D0E9E1CDD996E40042B5429852FCEFECADB318C1EA6BCD7B62F09E6792656` |
| Bytes changed | **1,353** (four FAT headers + four bodies, zero-filled surplus) |

Launcher note: start MAMP PRO through `C:\MAMPPRO\LauncherMAMPPRO.exe` — running
`net\MAMPPRO.exe` directly shows *"please start mamp pro with launcher"*.

---

## 2. TL;DR — install

```
1. exit MAMP PRO completely (tray icon -> Exit)
2. double-click  install.cmd   (asks for UAC)
3. done
```

`install.cmd` self-elevates, copies the engine to `C:\ProgramData\MampProPatch\`, backs up
the pristine `MAMPPRO.dll` once, and patches the build that is installed right now.

Manual control:

```powershell
# report only, writes nothing
C:\ProgramData\MampProPatch\MampProPatch.ps1 -DryRun

# patch now (also: double-click patch-now.cmd from this folder)
C:\ProgramData\MampProPatch\MampProPatch.ps1

# restore the original dll
C:\ProgramData\MampProPatch\MampProPatch.ps1 -Restore
```

Manual mode only — no scheduled task, no watcher (see §11).

---

## 3. What it does / what it does NOT do

**Does**

* Forces `MAMPPRO4.App::CheckDataForStartup` to `StartApp()` — the startup gate that
  decides between *launch*, *trial countdown* and *expired -> serial dialog*.
* Forces `MAMPPRO4.Utility.AppUtility::IsBought` to `true` — the paid flag read by the UI.
* Kills both serial-dialog triggers: `ControlPanel::MenuItem_Click_2` becomes `ret`,
  `ThreeButtonMessageBox::secbtn_Click_1` becomes its own cancel tail.
* Re-discovers every site by **method name** after a MAMP update, verifies by SHA-256 and
  opcode shape, and resolves the two call targets by name at patch time — no RVA or
  token is ever trusted.
* Refuses to write **anything** when any of the four gates is unrecognisable, and refuses
  to write when the module-wide dialog scan finds a construction path it does not know.

**Does not**

* Touch the metadata tables. No table, heap, stream, row count or size is rewritten —
  only bytes inside four method bodies at their existing `MethodDef.RVA`.
* Emulate a serial, patch the serial validator, or talk to any server. The
  `MP-…A|B|C` validation path is left exactly as shipped; the gates around it are cut.
* Survive a MAMP update by itself (manual mode — re-run `patch-now.cmd`).

---

## 4. How MAMP PRO's licensing actually works

Read out of the IL and metadata of `MAMPPRO.dll` (cross-checked against the decompiled
sources of this build).

| Piece | Token | Role |
|---|---|---|
| `App::CheckDataForStartup` | `0x06000285` | startup gate: reads the cached license state (trial 18 days / demo / expired) and either calls `App::StartApp` or falls into the nag/serial paths |
| `App::StartApp` | `0x06000286` | launches the real UI — the call the gate should have made unconditionally |
| `AppUtility::IsBought` | `0x060008C1` | 24-byte predicate: constructs the license cache (`newobj 0x0A0001D7`), tests the stored state, returns bool — read wherever the UI decides paid vs trial |
| `ControlPanel::MenuItem_Click_2` | `0x06000480` | menu handler; when not bought it does `new EnterSerial()` and shows the serial dialog |
| `ThreeButtonMessageBox::secbtn_Click_1` | `0x06000CDC` | third-button handler of the "your MAMP PRO has expired" message box; builds the same dialog or, on its cancel path, calls `set_serialtext(this, null)` |
| `EnterSerial::.ctor()` (paramless) | `0x060002F5` | the serial dialog itself — **constructed by exactly the two triggers above** |
| `EnterSerial::.ctor(args)` | `0x060002F6` | built only by `EnterSerial::OK_Click` (re-open after a submit) — deliberately left alone |
| `ThreeButtonMessageBox::set_serialtext` | `0x06000CD9` | writes the message box's serial text — the cancel tail already contains the right call |

The observed lifecycle: first launch starts an **18-day trial**; once the trial ends (or
the cache says *expired*) `CheckDataForStartup` routes into the serial dialog, and both
triggers above can pop `EnterSerial` at runtime. A valid serial writes a `bought` file and
stores the key in the local `mamp.db` (SQLite) — all local state. The patch does not
produce any of that state; it removes the code that demands it.

### Why four sites, not one

`CheckDataForStartup` only covers startup. The two triggers are reachable from the UI
after launch (menu click, expired-nag button), and `IsBought` drives the badges — patch
only the startup gate and MAMP still opens `EnterSerial` from a menu; patch only the
triggers and the badge/nag logic still reports trial. The four sites are the complete set
that a module-wide scan for `newobj EnterSerial::.ctor` confirms — see §8.

---

## 5. The four patches

All four bodies are **FAT** (12-byte header). Method identity on build 5.0.6.7029:

| # | Method | Token | Row | RVA | header @ file | Flags | maxstack | LocalVarSigTok | ilSize |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `MAMPPRO4.App::CheckDataForStartup` | `0x06000285` | 645 | `0x00008608` | `0x6808` | `0x301B` (EH+locals) | 6 | `0x11000016` | 1436 |
| 2 | `MAMPPRO4.Utility.AppUtility::IsBought` | `0x060008C1` | 2241 | `0x0002D4AC` | `0x2B6AC` | `0x3013` (locals) | 3 | `0x11000138` | 24 |
| 3 | `MAMPPRO4.Views.ControlPanel::MenuItem_Click_2` | `0x06000480` | 1152 | `0x0001B9DC` | `0x19BDC` | `0x301B` (EH+locals) | 6 | `0x110000AF` | 189 |
| 4 | `…ThreeButtonMessageBox::secbtn_Click_1` | `0x06000CDC` | 3292 | `0x00047490` | `0x45690` | `0x3013` (locals) | 2 | `0x110001F4` | 74 |

### 5.1 `CheckDataForStartup` — the startup gate

| | |
|---|---|
| Before (IL start) | `28 D5 01 00 0A 13 07 12 07 23 00 00 00 00 00 00 00 08 C0 …` — 1436 bytes: cache read, trial/demo/expired switch, nag paths |
| The gate's own early exit | `… 02 28 86 02 00 06 2A` → `ldarg.0; call StartApp; ret` (appears three times in the original) |
| After | `02 6F 86 02 00 06 2A` → `ldarg.0; callvirt StartApp; ret` (7 bytes) |

The replacement is the method's own happy-path sequence, made unconditional — emitted as
`callvirt` (`6F`) instead of `call` (`28`) so it carries a null check on `this`.
Header: flags `0x301B -> 0x3003`, CodeSize `1436 -> 7`, LocalVarSigTok `-> 0`,
maxstack 6 kept, the other 1429 bytes zero-filled.

```text
pristine IL sha256 : ea4e5d38ccc9badb79d150fd98753ccd6d2387f79c8df77367aab018ec002d96
patched  IL sha256 : 20094782101e967ed71dc2c8c9677ab40d2b2929e0064d524c5215304273a4b4
```

### 5.2 `IsBought` — the paid flag

| | |
|---|---|
| Before | `73 D7 01 00 0A 14 02 6F DA 01 00 0A 0A 06 2C 04 06 1C 33 02 17 2A 16 2A` (24 B) |
| | `newobj InitDataCache; …; callvirt …; stloc.0; ldloc.0; brfalse.s; …; ldc.i4.1; ret; ldc.i4.0; ret` |
| After | `17 2A` → `ldc.i4.1; ret` (2 bytes) |

```text
pristine IL sha256 : 760df438c1348e92850e5cb966774778cfab357f27c16e4e90fdad65521ae295
patched  IL sha256 : 3e652f9ec0ddcdd64c52c9cba261a1f70bba3ffa41ff4296d6eba45e6514b378
```

### 5.3 `MenuItem_Click_2` — serial dialog trigger 1

| | |
|---|---|
| Before | `73 F5 02 00 06 0A 06 6F DB 01 00 0A 26 06 6F EF 02 00 06 39 …` (189 B) |
| | first instruction is `newobj 0x060002F5` — the EnterSerial dialog |
| After | `2A` → `ret` (1 byte) |

```text
pristine IL sha256 : d9aee0f8fa157fd2b269be9e119d58ff286f7dd022fb1536ee1309ccde75ed96
patched  IL sha256 : 684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1
```

### 5.4 `secbtn_Click_1` — serial dialog trigger 2

| | |
|---|---|
| Before | `02 16 28 D5 0C 00 06 73 F5 02 00 06 … 02 28 3F 00 00 0A 2A 02 14 28 D9 0C 00 06 2A` (74 B) |
| After | `02 14 28 D9 0C 00 06 2A` → `ldarg.0; ldnull; call set_serialtext; ret` (8 bytes) |

The replacement is the method's **own cancel tail** (the last 8 bytes of the original) —
we simply make it unconditional, reusing the call target `0x06000CD9` the build already
contains:

```text
pristine IL sha256 : 59edc250078bb30224cc2f3acb5ddc5e0e3cd0249145f1419e28b9d5638a6f18
patched  IL sha256 : 0b12372047abea6a3a85d1cfdcfc8f2b29697344ba3320074eb3bdc95f551f12
```

### 5.5 Byte accounting

`tools/byte_diff.ps1` over pristine vs patched — all changed bytes live inside the four
body regions, nothing else in the file moves:

```text
total differing bytes: 1353
  0x6808..0x6DB0   CheckDataForStartup   1117   (5 header + 1112 body)
  0x2B6AC..0x2B6D0 IsBought                27   (5 header +  22 body)
  0x19BDC..0x19CA5 MenuItem_Click_2        146   (4 header + 142 body)
  0x45690..0x456E6 secbtn_Click_1           63   (5 header +  58 body)
```

The header deltas themselves (per FAT layout in §6):

```text
0x6808: 1B->03  0x680C: 9C->07  0x680D: 05->00  0x6810: 16->00  0x6813: 11->00
0x2B6AC: 13->03 0x2B6B0: 18->02 0x2B6B4: 38->00 0x2B6B5: 01->00 0x2B6B7: 11->00
0x19BDC: 1B->03 0x19BE0: BD->01 0x19BE4: AF->00 0x19BE7: 11->00
0x45690: 13->03 0x45694: 4A->08 0x45698: F4->00 0x45699: 01->00 0x4569B: 11->00
```

---

## 6. FAT method bodies: how the rewrite stays load-safe

A method body header is **TINY** (1 byte: `(ilSize << 2) | 2`, maxstack implied 8) or
**FAT** (12 bytes). Every target here is FAT — this is what the writer does to it:

```text
offset +0  WORD  Flags        format=3 | MoreSects 0x8 | InitLocals 0x10 | 0x3000
offset +2  WORD  MaxStack     kept as-is (6 / 3 / 6 / 2 - every replacement fits)
offset +4  DWORD CodeSize     rewritten to the new IL length
offset +8  DWORD LocalVarSig  zeroed - the new bodies declare no locals
offset +12       IL bytes     new code, surplus zero-filled to the old CodeSize
```

* **MoreSects cleared** (`0x301B/0x3013 -> 0x3003`): the original `CheckDataForStartup`
  and `MenuItem_Click_2` carry an exception-handler section behind the code. The
  replacements have no EH, so the bit is dropped and the CLR never reads the stale
  clause bytes that still sit past the new body — they become unreferenced padding.
* **InitLocals cleared + LocalVarSigTok zeroed**: `InitLocals` with a signature that no
  longer matches the body is exactly the kind of mismatch that fails at JIT time. Both
  go together, always.
* **RVA never moves**: `MethodDef.RVA` still points at the same 12-byte header, the
  section table is untouched, and no heap or table row is edited — the loader sees a
  normal module.
* **Surplus zero-filled**: the new body is always shorter than the original (7 ≤ 1436,
  1 ≤ 189, …), so `PatchIl` writes the code, then `0x00` to the old end. Deterministic
  output: same pristine file + same patch = same bytes, every time.

If a future build ships a target with a *bigger* replacement than its original body,
`PatchIl` returns false and the engine exits 5 without writing — it never grows a body
in place.

---

## 7. The matcher (how it survives updates)

`MampProPatch.ps1` never stores an offset. Per site, in order:

| # | Condition | Action | Tier |
|---|---|---|---|
| 1 | `FindRow(fullName)` hits the metadata name table | patch | `exact` |
| 2 | SHA-256 of current IL == known patched value | skip (idempotent) | — |
| 3 | opcode shape == patched shape | skip (idempotent) | — |
| 4 | SHA-256 of current IL == known pristine value | patch | `exact` |
| 5 | IL differs (recompiled), but the **opcode skeleton** still matches | patch | `shape` |
| 6 | Declaring type gone: same short name under any type, shape matches | patch | `fuzzy` |
| 7 | Shape differs too | **refuse everything**, record, notify once | `dark` |

Shapes are skeletons with every operand masked to `-1` (wildcard) plus the expected body
length — long bodies use a masked prefix + length, short ones are fully enumerated:

```powershell
# IsBought - newobj <any>; dup; ldarg.0; callvirt <any>; stloc.0; ldloc.0; brfalse.s <any>; ...
Shapes        = @( @{ Len = 24; P = [int[]](0x73,-1,-1,-1,-1,0x14,0x02,0x6F,-1,-1,-1,-1,
                                            0x0A,0x06,0x2C,-1,0x06,0x1C,0x33,-1,0x17,0x2A,0x16,0x2A) } )
PatchedShapes = @( @{ Len =  2; P = [int[]](0x17,0x2A) } )
```

The two call replacements are built at patch time from **name-resolved** callees
(`MAMPPRO4.App::StartApp`, `…ThreeButtonMessageBox::set_serialtext`) — their MethodDef
tokens move between builds, so the engine looks the rows up and emits the bytes, then
verifies the result by SHA-256.

**All-or-nothing.** Any dark site (or a callee that disappeared) means **no site is
written** — exit 4, target untouched, one MessageBox per build deduped through
`state.json` (capped at 50 entries). A half-patched MAMP would still show the dialog
somewhere; the engine would rather report than ship a maybe.

**Fast path.** Before parsing 2 MB of metadata, the file's SHA-256 is compared against
`lastGood` in `state.json`. Equal → one hash, done (this is what a second run costs).

---

## 8. The module-wide ctor gate

Patching four known methods is not enough if some *fifth* path builds the dialog. Before
any write the engine scans **every method body in the module** for
`newobj <token>` where `<token>` is each `MAMPPRO4.EnterSerial::.ctor`, and requires:

```text
newobj 0x060002F5 (paramless)  ->  exactly { MenuItem_Click_2, secbtn_Click_1 }   (the two triggers)
newobj 0x060002F6 (arguments)  ->  exactly { EnterSerial::OK_Click }              (allowed, untouched)
any other constructor site     ->  REFUSE, exit 4, nothing written
```

After the patch (and again, independently, on the file about to be swapped in):

```text
newobj 0x060002F5  ->  no occurrences left, module-wide
newobj 0x060002F6  ->  still exactly { EnterSerial::OK_Click }
```

Observed on this build:

```text
[gate] dialog ctor 0x060002F5 - construction sites inside allowed set
```

The gate runs on *unpatched* state too — it identifies the dialog ctor by which rows
construct it, so a partially-patched file is still classified correctly.

---

## 9. Why in-place instead of a rewriter

Two roads were walked before this one shipped.

**The rewriter (dnlib).** The first working patcher rebuilt the module through dnlib.
Functionally correct — and a completely different file: 2,031,616 → 2,054,144 bytes,
every RVA shifted, metadata rewritten, a new SHA-256 that belongs to the toolchain rather
than the patch. Every update meant re-proving the whole assembly still loads, and the
diff stops being evidence — you cannot say "these 1,353 bytes" about a rewrite.

**The version trap.** A patch helper compiled on .NET 9 that does
`module.Import(typeof(<WPF type>))` emits an assembly reference to
`PresentationCore 9.0.0.0`. MAMPPRO is .NET 6: the reference never resolves, the JIT
throws `FileNotFoundException` when it first compiles the patched method — the app dies
at the gate you just patched, with a crash event and nothing else to show for it.

So the rules here: **never import a type from an assembly the target does not have**, and
**never rewrite what you can overwrite.** Kill triggers with `ret` and same-module call
tokens only; keep the metadata tables byte-identical. What loads after the patch is the
vendor's own file, minus four bodies — which is why the proof in §12 is a window count
and a crash log, not a hope.

---

## 10. Files

```text
MampPro/
  README.md                        this file
  install.cmd                      self-elevating installer (double-click me)
  uninstall.cmd                    restores the original MAMPPRO.dll
  patch-now.cmd                    manual re-patch (self-elevating, no task/watcher)
  Install-MampProPatch.ps1         copies engine, one-time backup, first run
  MampProPatch.ps1                 the engine: matcher + ctor gate + verifier + writer
  MampCli.cs                       PE + CLI metadata reader, TINY/FAT body rewriter
                                   (runtime dependency of the engine — stays at top level)

  tools/
    byte_diff.ps1                  enumerates every differing byte between two builds
    dump_il.ps1                    raw, byte-exact IL dumper (TINY + FAT, ldstr from #US)
```

Runtime layout after install:

```text
C:\ProgramData\MampProPatch\
  MampProPatch.ps1
  MampCli.cs
  mamp-patch.log                   one line per write (before/after sha, counts)
  versions.txt                     one line per vendor build seen (date, sha, size)
  state.json                       { lastGood, warned[], when }
  backup\MAMPPRO.dll.orig          pristine, refreshed whenever a vendor build is seen

C:\MAMPPRO\net\
  MAMPPRO.dll.bak                  one-time in-place backup (written on first patch)
```

---

## 11. Manual mode

MAMP PRO ships with **no scheduled task and no watcher** — the patch is applied once and
stays until MAMP updates. When an update replaces `MAMPPRO.dll`:

```powershell
# double-click patch-now.cmd in this folder, or:
C:\ProgramData\MampProPatch\MampProPatch.ps1
```

If MAMP PRO is running the engine exits `3` (the dll is locked) — exit MAMP from the tray
and re-run. The engine never kills the app for you; MAMP's processes refuse `taskkill`
(self-protection), which is exactly the sort of thing you want a patcher *not* to work
around silently.

---

## 12. Verification / evidence

### Discovery (DryRun on the pristine build)

```text
MAMP PRO license gate patch
  target : C:\MAMPPRO\net\MAMPPRO.dll
  size   : 2,031,616 bytes
  method : 5,490
  sha256 : 332819BB1F0B552EA4FD49A3AC994E396A2677D7D1996AFF66C540D0093980E8

  MAMPPRO4.App::CheckDataForStartup
      rva 0x00008608  body 0x6808  il@0x6814  ilSize 1436  hdr FAT  fat 0x301B  maxstack 6
      new IL      : 026F860200062A   [exact]  sha 20094782101e967e
  MAMPPRO4.Utility.AppUtility::IsBought
      rva 0x0002D4AC  body 0x2B6AC  il@0x2B6B8  ilSize 24  hdr FAT  fat 0x3013  maxstack 3
      new IL      : 172A   [exact]  sha 3e652f9ec0ddcdd6
  MAMPPRO4.Views.ControlPanel::MenuItem_Click_2
      rva 0x0001B9DC  body 0x19BDC  il@0x19BE8  ilSize 189  hdr FAT  fat 0x301B  maxstack 6
      new IL      : 2A   [exact]  sha 684888c0ebb17f37
  MAMPPRO4.Windows.ThreeButtonMessageBox::secbtn_Click_1
      rva 0x00047490  body 0x45690  il@0x4569C  ilSize 74  hdr FAT  fat 0x3013  maxstack 2
      new IL      : 021428D90C00062A   [exact]  sha 0b12372047abea6a

  [gate] dialog ctor 0x060002F5 - construction sites inside allowed set
  DRY RUN: 4 to patch, 0 already patched, 0 unknown
```

### The write + independent re-read

```text
  [gate] dialog ctor 0x060002F5 - construction sites inside allowed set
  vendor build backed up -> C:\ProgramData\MampProPatch\backup\MAMPPRO.dll.orig
  patched [exact]: CheckDataForStartup (startup gate)
  patched [exact]: IsBought (bought flag)
  patched [exact]: MenuItem_Click_2 (dialog trigger 1)
  patched [exact]: secbtn_Click_1 (dialog trigger 2)

  sha256 before : 332819BB1F0B552EA4FD49A3AC994E396A2677D7D1996AFF66C540D0093980E8
  sha256 after  : 913D0E9E1CDD996E40042B5429852FCEFECADB318C1EA6BCD7B62F09E6792656
  4 patched, 0 skipped, 0 dark
```

The verifier chain before anything touches the target: every patched row re-hashed
against the bytes the engine meant to write → all four patched shapes re-checked →
module-wide `newobj` scan must be empty → the temp file is written, **loaded fresh by a
second reader** and re-verified → only then does an atomic `Move-Item` swap it in. Any
failure deletes the temp file and exits 5 with the target untouched.

Re-read of the installed file (fresh parse, not the in-memory copy):

```text
MAMPPRO4.App::CheckDataForStartup
    il=026F860200062A sha=20094782101e967ed71dc2c8c9677ab40d2b2929e0064d524c5215304273a4b4
    hdrBytes=033006000700000000000000 fatflags=0x3003 localsig=0x00000000
MAMPPRO4.Utility.AppUtility::IsBought
    il=172A sha=3e652f9ec0ddcdd64c52c9cba261a1f70bba3ffa41ff4296d6eba45e6514b378
    hdrBytes=033003000200000000000000 fatflags=0x3003 localsig=0x00000000
MAMPPRO4.Views.ControlPanel::MenuItem_Click_2
    il=2A sha=684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1
    hdrBytes=033006000100000000000000 fatflags=0x3003 localsig=0x00000000
MAMPPRO4.Windows.ThreeButtonMessageBox::secbtn_Click_1
    il=021428D90C00062A sha=0b12372047abea6a3a85d1cfdcfc8f2b29697344ba3320074eb3bdc95f551f12
    hdrBytes=033002000800000000000000 fatflags=0x3003 localsig=0x00000000
newobj EnterSerial ctor F5 users = (none)
newobj EnterSerial ctor F6 users = MAMPPRO4.EnterSerial::OK_Click
```

Flags word `0x3003` = format 3, no MoreSects, no InitLocals; maxstack (words at +2) kept
at 6 / 3 / 6 / 2; CodeSize at +4 equals the new IL length.

### Runtime proof (this machine, build 5.0.6.7029)

```text
launcher -> MAMPPRO pid 3316 at 17:20:59
T+300s   proc: MAMPPRO responding=True title=MAMP PRO 5
         win: pid=3316 [199116] MAMP PRO 5            <- the only visible window
         crash events: none (NET Runtime | Application Error x "MAMP", since 17:15)
```

Single window, no `EnterSerial` dialog at any checkpoint, no crash events, process
responding after five minutes of uptime. `MAMPPROService` / `MAMPROSysTray` left running
the whole time — they don't hold the dll open (verified: the engine's lock probe passes
with only those two alive).

### Idempotency, restore, re-patch

```text
run 2     : already clean (fast path, sha 913D0E9E1CDD996E) - done        exit 0
-Restore  : restored from C:\ProgramData\MampProPatch\backup\MAMPPRO.dll.orig
            SHA256 = 332819BB1F0B552EA4FD49A3AC994E396A2677D7D1996AFF66C540D0093980E8
re-patch  : 4 patched, sha256 after = 913D0E9E1CDD996E40042B5429852FCEFECADB318C1EA6BCD7B62F09E6792656
```

The patched SHA-256 is a property of the patch, not of this machine: pristine → patch
reproduced `913D0E9E…` twice in a row, plus once more on an independent temp copy.

### The matcher against four simulated updates

Run on temp copies of the pristine dll (targets/backup dirs per sim, `-NoNotify`):

```text
normal build                        -> exact : 4 patched                         exit 0
recompile, newobj token shifted     -> shape : 4 patched (IsBought at shape)     exit 0
gate opcode corrupted               -> dark  : 0 patched, REFUSED                exit 4
                                       (target byte-identical to pre-run state)
declaring type renamed (same len)   -> fuzzy : 4 patched (MenuItem_Click_2
                                       found as MAMPXRO4.Views.ControlPanel::…)  exit 0
```

---

## 13. Rollback

```powershell
# one step
C:\ProgramData\MampProPatch\MampProPatch.ps1 -Restore
```

`-Restore` prefers the version-aware `backup\MAMPPRO.dll.orig`, then `MAMPPRO.dll.bak`,
then `MAMPPRO.dll.orig` next to the dll. It refuses while the dll is write-locked
(exit 3 — exit MAMP first) and clears `lastGood` so the next run re-scans from scratch.

Full removal:

```text
uninstall.cmd    -> restores the dll (same order as above)
```

---

## 14. Regenerating the analysis

```powershell
# 1. method table: token, row, Type::Method, RVA, ilSize, ilOffset
Add-Type -Path .\MampCli.cs
$cli = New-Object MampCli
$cli.Load('C:\MAMPPRO\net\MAMPPRO.dll')
$cli.Lines | Set-Content mamp_methods.tsv      # 5,490 rows

# 2. raw IL for specific tokens (byte-exact, TINY + FAT, ldstr decoded from #US)
.\tools\dump_il.ps1 -Path C:\MAMPPRO\net\MAMPPRO.dll -Tokens "0x06000285,0x060008C1,0x06000480,0x06000CDC"

# 3. prove a patch is N bytes and nothing else
.\tools\byte_diff.ps1 -A C:\MAMPPRO\net\MAMPPRO.dll.orig -B C:\MAMPPRO\net\MAMPPRO.dll

# 4. report against the live build without writing
.\MampProPatch.ps1 -DryRun
```

`MampCli.cs` exposes what the engine keys off: `FindRow` / `FindRowsInType` /
`FindRowsByName` (identity), `IlSha` / `IlHex` / `IlBytes` (verification),
`FatFlags` / `MaxStack` / `LocalVarSig` (header facts), `RowsWithToken` (the ctor-gate
scan), `PatchIl` (the TINY/FAT rewrite in §6).

---

## 15. Failure modes

| symptom | cause | what it says |
|---|---|---|
| exit `0`, nothing changed | file already patched | `already clean (fast path, sha …) - done` |
| exit `3` | MAMP PRO is running, dll write-locked | `MAMPPRO.dll is locked - exit it from the tray first` |
| exit `4` + one MessageBox | a gate was rewritten by a MAMP update | `REFUSED: N dark site(s) - nothing written` |
| exit `4`, ctor message | some unknown method builds `EnterSerial` | `[gate] EnterSerial ctor also constructed by: <method>` |
| exit `4`, missing callee | `StartApp` / `set_serialtext` renamed away | `callee not found: … - NOT touched` |
| exit `5` | post-write or re-read verify failed | `FAILED … verify` — temp deleted, target untouched |
| exit `1` | no write permission on `C:\MAMPPRO\net` | `access denied writing … run … elevated` |
| exit `2` | dll missing / not a CLI assembly | `target not found` / `not a loadable CLI assembly` |
| notification repeats | — | deduped per site label in `state.json` (cap 50) |
| no `.orig` refresh | file was not a pristine vendor build | backup only refreshes when at least one site was pristine |

The engine prefers failing loudly over patching the wrong method: a 5,490-row method
table contains plenty of ways to break an app by guessing.

---

## 16. Limits

* Client-side gates only. MAMP's own update, download and account services are not
  touched, and the serial validator itself is not bypassed or faked — the code that
  *asks* for a license state is cut, nothing else.
* Verified on build **5.0.6.7029** (`.NET 6`, 5,490 methods). Later builds re-enter the
  matcher: exact → shape → fuzzy, else dark (refuse + notification).
* The trial/bought state files (`bought`, `mamp.db`) are not modified — with the gates
  cut they are simply no longer consulted at startup.
* Vendor binaries (`MAMPPRO.dll`, the launcher, MAMP itself) are **not** in this
  repository.

---

*Analysis and patching performed against a locally installed copy. Offsets, tokens, RVAs
and hashes are from build 5.0.6.7029; only the four method names, their opcode shapes and
the `MAMPPRO4` namespaces are expected to survive into future builds.*
