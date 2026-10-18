# Internet Download Manager — License Gate Unlock (native x86 patch)

Local patcher for Internet Download Manager (Windows download manager) that removes the
client-side license gates: no trial countdown, no trial-expiry nags, no "your serial is not
genuine" dialog — IDMan.exe starts as if the check came back clean.

Everything here operates on your own installation, on disk, with no network calls and no
license server interaction. It is an analysis of a shipped native binary and a byte-level
patch of it: **29 bytes of 6,201,712 actually differ**, written across four sites — two that
neutralise the license gates, two that change what the About dialog prints.

---

## Table of contents

1. [Current version / verified build](#1-current-version--verified-build)
2. [TL;DR — install](#2-tldr--install)
3. [What it does / what it does NOT do](#3-what-it-does--what-it-does-not-do)
4. [How IDM's licensing actually works](#4-how-idms-licensing-actually-works)
5. [The four patches](#5-the-four-patches)
6. [The function that could NOT be patched](#6-the-function-that-could-not-be-patched)
7. [The matcher (how it survives updates)](#7-the-matcher-how-it-survives-updates)
8. [Verification](#8-verification)
9. [Exit codes](#9-exit-codes)
10. [Limits](#10-limits)

---

## 1. Current version / verified build

| field | value |
|---|---|
| target | `C:\Program Files (x86)\Internet Download Manager\IDMan.exe` |
| version | 6.43.15.2 |
| size | 6,201,712 bytes |
| machine | `0x14C` (i386) |
| image base | `0x400000` |
| ASLR | on (`DllCharacteristics 0x8140` — `DYNAMICBASE` + `HIGH_ENTROPY_VA` + `NX_COMPAT`) |
| sections | 5 — `.text .rdata .data .rsrc .reloc` |
| sha256 pristine | `E3FC655A335E17A6FDD09A9B315291D0C8863180F0D801E5DD7433C9E56AFBD8` |
| sha256 patched  | `FF658CE12E67D813037B68F54FA7DC0F63B7787641CFF8E095D83814E2704547` |
| bytes written | **53**, across 4 sites |
| bytes differing | **29** (the rest of the written bytes coincidentally already matched) |
| companion | `idmBroker.exe` 6.35.9.1 (browser-integration broker — carries no license gates, untouched) |

A different IDM build gets a different hash. That is expected: see
[§7](#7-the-matcher-how-it-survives-updates).

---

## 2. TL;DR — install

```
install.cmd          (backs up IDMan.exe, patches, writes state.json)
patch-now.cmd        (re-patch after an IDM update — manual mode, no task)
uninstall.cmd        (restores the pristine IDMan.exe, removes state)
```

All three self-request UAC. Nothing is scheduled, nothing is watched. When IDM updates
itself it overwrites `IDMan.exe` with a fresh signed build, the patch is gone, and
`patch-now.cmd` puts it back.

---

## 3. What it does / what it does NOT do

**Does** — forces the two functions that decide *whether to continue* to continue:

- the startup license check reports `status 0` (clean) without ever reading the registry,
  validating a serial, or reaching the phone-home path;
- the nag/exit gate reports `1` (continue) so the shutdown branch after it is never taken;

and corrects the two strings the About dialog prints:

- the version line always reads `… Full` instead of `… Trial`;
- the licensee line reads `Registered Version` instead of the shipped placeholder
  `Unregistered Version`.

The last two are **presentational**. They change what is on screen and nothing else — no
gate, no counter, no global and no code path is affected by them. See
[§5](#5-the-four-patches).

**Does not:**

- **Emulate a serial.** No serial is written anywhere — not to
  `HKCU\Software\DownloadManager`, not to the file. The registry on a fresh install carries
  no serial values, and this patch does not add any.
- **Patch the serial validator or its crypto.** The format check (`0x702910`: length `0x17`,
  dashes at fixed positions) and the serial crypto (`0x760790`) are left exactly as shipped.
  The gates *around* them are cut, the code inside them is untouched.
- **Touch the trial-length selector or the day counters.** See [§4](#4-how-idms-licensing-actually-works).
- **Modify, disable or intercept any network call.** The phone-home path is not patched,
  not stubbed, not redirected. Update traffic and normal operation are untouched.
- **Run in the background.** No service, no scheduled task, no injector, no driver.

---

## 4. How IDM's licensing actually works

The relevant surface is all inside `IDMan.exe`, and it is native x86 — no metadata tables,
no method names, no IL. Everything below was established by static disassembly plus
Frida in-memory instrumentation of a live instance.

### The startup path

```
InitInstance 0x632070
  └─ call 0x630B40                 startup license check
       ├─ reads HKCU\Software\DownloadManager
       ├─ format-validates any serial found  (0x702910)
       ├─ runs serial crypto                 (0x760790)
       └─ returns a status code 0..12
  └─ jump table 0x6339CC            one branch per status
       └─ status 0 ─► 0x6331C6
            └─ call 0x62CEF0        enforcement gate, 0x864-byte SEH frame
                 ├─ returns 1 ─► jmp 0x63340D ─► esi==0 ─► continue, main window comes up
                 └─ returns 0 ─► 0x6334AA ─► quit
```

Both `0x630B40` and `0x62CEF0` are **exit-decision points**, not validators. Neither
computes anything the rest of the program needs later — they only answer "is this clean?"
and the caller branches on the answer. That is what makes a three-byte and a six-byte
replacement safe: no state is produced here that anything downstream reads.

There are three callers of the gate (`0x6331C9`, `0x633461`, `0x633496`), all of them in
the same startup sequence, and one caller of the check (`0x632A1A`).

### The globals — and why none of them are patched

| address | role | file-initial | verdict |
|---|---|---|---|
| `0x95bd24` | trial-**length** selector | `1` | **leave alone** |
| `0x95bd28` | trial length in days | `30` (`0x1E`) | leave alone |
| `0x968d00` | "license check failed" flag | `0` | leave alone |

`0x95bd24` looks like a "registered" flag and is not one. The day count is computed at
`0x62cf37`:

```asm
neg  eax
sbb  eax, eax
and  eax, 0x0F
add  eax, 0x0F        ; 15 or 30, written to [0x95bd28]
```

with `0x95bd24 == 0` selecting **15** days and `!= 0` selecting **30**. On a pristine
install it ships as `1`, which is already the *better* of the two states. The only code
that ever writes it is `0x630e09 mov [0x95bd24], 0`, which fires when a well-formed serial
is detected — and after this patch that code is never reached, because `0x630B40` returns
before it gets there.

So the healthy file-initial values are preserved *by construction*: both patched functions
run **before** the day-write, and returning early skips the code that would change them.

The check-failed flag `0x968d00` is set at `0x632a31` when `0x630b40` returns nonzero and
cleared at `0x63345a`. A forced `0` leaves it at its pristine `0`.

Measured live on the patched process:

```
b95bd24 = 1     b95bd28 = 30     f968d00 = 0
```

### The verdict function

Beyond startup there is a second, deeper check — a master verdict at `0x7F2DBF` — reached
from runtime re-checks at `0x669ABE`, `0x675140` and `0x5E2B91`. Those callers compare its
result against zero and quit when it is nonzero, going through a fatal-message switch at
`0x62B7B0` (jump table `0x62B9DC`, cases 2..12) and a quit path at `0x7F27CD` / `0x669620`.

It is **not patched**, and it is the single most important negative result in this
analysis. See [§6](#6-the-function-that-could-not-be-patched).

---

## 5. The four patches

Sites 1 and 2 are prologue replacements, written before any stack frame is allocated — so
neither touches `ESP`, `EBP` or any callee-saved register on the way out. The caller's
stack stays balanced and the return value lands in `EAX`, which is exactly what the callers
read. The remainder of each original body becomes dead code behind the `ret` and is never
reached.

Sites 3 and 4 are not code replacement in that sense: one is a single branch byte, the other
a UTF-16 string inside a dialog template. Neither allocates a frame, touches a register or
writes a global.

### Patch 1 — startup validator

| | |
|---|---|
| runtime VA (this build) | `0x630B40` |
| RVA | `0x050B40` |
| **file offset** | **`0x04FF40`** |
| original | `55 8D AC 24 DC FB FF FF 81 EC 24 04 00 00 …` |
| | `push ebp; lea ebp,[esp-0x424]; sub esp,0x424; push -1; push SEH; …` |
| patched | `31 C0 C3` |
| | `xor eax,eax; ret` — always reports status 0 (clean) |
| bytes | 3 |

### Patch 2 — nag / exit gate

| | |
|---|---|
| runtime VA (this build) | `0x62CEF0` |
| RVA | `0x04CEF0` |
| **file offset** | **`0x04C2F0`** |
| original | `55 8D AC 24 9C F7 FF FF 81 EC 64 08 00 00 …` |
| | `push ebp; lea ebp,[esp-0x864]; sub esp,0x864; push -1; push SEH; …` |
| patched | `B8 01 00 00 00 C3` |
| | `mov eax,1; ret` — always reports "continue" |
| bytes | 6 |

### Patch 3 — About dialog, version suffix

The About dialog (`RT_DIALOG` id `100`) builds its version line in
`CAboutDlg::OnInitDialog` and picks between two literals sitting side by side in `.rdata`:

```asm
0x0039A1  GetWindowText([esi+0x184], buf, 0x40)   ; control 0x04EE's current text
          test eax, eax
          jle  0x003A75                           ; empty -> leave it alone

0x0039C1  CString s1
0x0039D0  39 1D 24 BD 77 00   cmp dword [0x77BD24], ebx   ; ebx = 0
0x0039D6  74 07               je   0x0039DF
0x0039D8  68 50 6E 69 00      push 0x696E50                ; "Trial"
0x0039DD  EB 05               jmp  0x0039E4
0x0039DF  68 48 6E 69 00      push 0x696E48                ; "Full"
0x0039E4  E8 77 F6 FF FF      call 0x3060                  ; CString::operator=

          … CString s2 = s1 + [0x788E50]                   ; the space separator
          … Format(s3, "%s%s", buf, s2)
          … SetWindowText([esi+0x184], s3)
```

`0x77BD24` (disk) is the trial global from [§4](#4-how-idms-licensing-actually-works) — file
value `1` on every trial build — so the `je` is never taken and the line ends in `Trial`.
Flipping the branch to `EB` (`jmp`) makes it unconditional and the line always ends in
`Full`. The `cmp` stays, now dead; nothing else in the sequence changes.

| | |
|---|---|
| RVA | `0x0039D6` |
| **file offset** | **`0x002DD6`** |
| section | `.text` |
| original | `74 07` (`je 0x0039DF`) |
| patched | `EB 07` (`jmp 0x0039DF`) |
| bytes | 2 |

### Patch 4 — About dialog, licensee line

The same dialog ships the static control `0x049D` — the one under the group box "This
product is licensed to:" — with a placeholder baked into the resource template:

```
Unregistered Version        UTF-16, file offset 0x38DB5C, .rsrc
```

That placeholder is only ever replaced at runtime by one path, and it is gated twice:

```asm
0x003683  39 1D 24 BD 77 00   cmp dword [0x77BD24], ebx
0x003689  0F 85 …             jne 0x0039A1             ; trial -> skip the whole read
          … RegOpenKeyExA(HKLM, "SOFTWARE\Internet Download Manager", …)
          … RegQueryValueExA(…) x2
          … if (s.IsEmpty()) jmp 0x0037C7              ; empty -> leave the placeholder
0x0037C2  E8 …                 call 0x211B14            ; CWnd::SetDlgItemText(0x049D, s)
```

On a trial build `0x77BD24` is `1`, so the branch is taken and the registry read never
runs. Even with that branch forced open it would still fail: a trial install has no
licensee value under `HKLM\SOFTWARE\Internet Download Manager`, the `CString` comes back
empty, and the `IsEmpty` check skips the `SetDlgItemText`. The placeholder is what stays on
screen either way.

So the placeholder itself is replaced, in place, in the resource. The dialog parser walks
from item to item off the string terminator, which is why the replacement has to be exactly
the same length as the original — 20 UTF-16 characters plus a 2-byte terminator, 42 bytes
on both sides:

```
before   U n r e g i s t e r e d   V e r s i o n \0
after    R e g i s t e r e d   V e r s i o n   _  _ \0
                                                              ^ ^ trailing spaces
```

The two trailing spaces are invisible in a left-aligned `STATIC` control, so it renders as
`Registered Version`.

| | |
|---|---|
| RVA | `0x0399F5C` |
| **file offset** | **`0x38DB5C`** |
| section | `.rsrc` |
| original | `55 00 6E 00 … 6E 00 00 00` — `"Unregistered Version"` UTF-16 |
| patched | `52 00 65 00 … 20 00 00 00` — `"Registered Version  "` UTF-16 |
| bytes | 42 |

If IDM is ever given a real serial, `0x77BD24` goes to `0` and the registry path above runs
and overwrites this control with the real licensee name — the patch neither blocks nor
conflicts with that.

**53 bytes written** (3 + 6 + 2 + 42), of which 29 actually change value. Nothing else in
the file differs — no header, no section table, no imports, no relocations, and in the
resources nothing but this one string.

### Why these signatures are ASLR-proof

All four patches contain **zero absolute addresses**, so they are correct under any slide.
Sites 1 and 2 patch instructions whose operands are stack displacements; site 3 patches a
relative short-jump displacement; site 4 patches character codes. None of the four has a
relocation in it.

For sites 1 and 2, the *signatures* are also relocation-independent:
`lea ebp,[esp-0x424]` and `sub esp,0x424` are stack displacements, not addresses. Those
signatures are deliberately cut **before** the `push imm32` that follows the prologue
(`68 70 52 66 00` = `push 0x665270`, the SEH handler). That immediate *is* an absolute
address and is relocated by the loader. Note the file always contains the **unrelocated**
form — relocation happens in memory at load time, so a disk patch is identical on every
machine for a given build.

Site 3's signature *does* span an immediate — `68 50 6E 69 00` is `push 0x696E50` — but it
is only read, never written: the patch covers the two branch bytes in front of it, and the
relocated address is never compared against anything.

---

## 6. The function that could NOT be patched

The obvious move is to neutralise the master verdict directly:

```
0x7F2DBF  →  31 C0 C3    (xor eax,eax; ret — "verdict: clean")
```

**This kills the process.** Not a crash — a clean exit, no event in the Application log,
no fault bucket. Bisected and confirmed:

| sites patched | result |
|---|---|
| `gate` | **ALIVE** — clean title `Internet Download Manager 6.43`, `Responding=True` |
| `gate,validator` | **ALIVE** — clean title, no trial suffix |
| `gate,validator,verdict` | **DEAD** — exits during startup, no window |

The reason is structural. `0x7F2DBF` has roughly **100 callers**, and most of them do not
care about its return value — they depend on its **side effects**: it reads `[esi+0x60]`,
it issues IAT calls, it advances state the rest of the run expects to exist. Returning
before any of that runs starves downstream code, which then exits through its own path.

This is exactly the failure mode a naive patch would ship. A function whose return value
*looks* like a simple flag but whose body is load-bearing is the classic trap: the flag is
the decoy, the side effects are the contract. So the verdict stays untouched, and the
patch is confined to the two decision points whose entire job is to return a value.

Because the patch only covers the startup gates, **update traffic and runtime behaviour are
unaffected** — the phone-home path still executes exactly as shipped whenever it is
reached.

---

## 7. The matcher (how it survives updates)

There are no symbol names in a native binary to re-find after an update. Identity here is a
**byte signature scanned inside a named section** — `.text` for sites 1–3, `.rsrc` for
site 4 — resolved through three tiers:

| tier | when | how |
|---|---|---|
| `already` | the replacement bytes are already at the known offset | skip, refresh `state.json` |
| `exact` | file hashes to the known pristine build | signature must be sitting at the known offset, else refuse |
| `shape` | a different build — signature found **exactly once** in its section | patch wherever it landed |
| `dark` | signature absent, **or found 2+ times** | refuse, write nothing, exit 4 |

All sites are classified **before anything is written**. One ambiguous site refuses the
whole patch — all-or-nothing.

### Why "found 2+ times" matters here

`startup_validator`'s first 13 bytes are *not* unique. `push ebp; lea ebp,[esp-0x424];
sub esp,0x424` is a common MFC prologue, and this build contains four of them:

```
0x04FF40: … 68 70 52 66 00 …    ← TARGET   (SEH handler 0x665270)
0x0783E0: … 68 AB 8C 66 00 …             (0x668CAB)
0x0BD820: … 68 7B D6 66 00 …             (0x66D67B)
0x0BDB60: … 68 CB D6 66 00 …             (0x66D6CB)
```

They are identical for 17 bytes and diverge only at the SEH handler address. A naive
shape-scan on the prologue alone would have picked one of the wrong three and patched an
unrelated function.

The signature is therefore extended to **18 bytes** — one byte into that address — which
lands exactly once. `nag_exit_gate` was already unique at 13 bytes. Sites 3 and 4 needed no
such care: a branch byte surrounded by literal immediates, and a 20-character English
string, both land exactly once on the first try.

```
startup_validator     18 bytes  558dac24dcfbffff81ec240400006aff6870              [.text]  1 hit
nag_exit_gate         13 bytes  558dac249cf7ffff81ec640800                        [.text]  1 hit
about_version_full    14 bytes  740768506E6900EB0568486E6900                     [.text]  1 hit
about_licensee_text   42 bytes  55006e0072006500670069007300740065007200…          [.rsrc]  1 hit
```

Site 4's signature is the string including its terminator. Scanning for the characters
alone would also match any other dialog that happens to say "Unregistered Version"; the
terminator plus the `.rsrc` section scope keeps it at one.

Prove it yourself before trusting a new build:

```powershell
.\tools\dump_pe.ps1 -Path "C:\Program Files (x86)\Internet Download Manager\IDMan.exe" -Scan -Sig 558dac24dcfbffff81ec240400006aff6870
```

`UNIQUE` → the shape tier is safe. `AMBIGUOUS` or `ABSENT` → the engine will refuse, and
that refusal is the correct answer for a build this analysis does not cover.

### The fast path, and what happens when the engine grows

`state.json` records `lastGoodSha` so a repeat run can confirm "still the binary I
patched" without re-scanning. That alone is not a safe condition: `patch-now.cmd` does not
pass `-Force`, and a `state.json` left behind by an **older** engine records the hash of
*its* patch set. A newer engine carrying extra sites would see that hash match, print
`already patched`, and exit — never applying the sites it added.

So the fast path requires **both**:

- `state.lastGoodSha` equals the file's current hash, **and**
- `state.patchedSha` equals the hash *this* engine would produce.

A state written by a different patch set fails the second condition and falls through to a
full re-scan, where the tiers above resolve each site — `already` for the ones already in
place, `exact`/`shape` for the new ones. On a 2-site install upgraded to this engine the
run reports:

```
[i] state.json is from an older patch set - re-checking all sites
  startup_validator   already @ 0x04FF40
  nag_exit_gate       already @ 0x04C2F0
  about_version_full  shape   @ 0x002DD6
  about_licensee_text shape   @ 0x38DB5C
  [ok] 4 sites patched, 53 bytes total
```

The same guard is what makes an engine *downgrade* safe: an old engine meeting a
newer-engine state re-checks rather than trusting a hash it cannot reproduce.

---

## 8. Verification

**Static**

```
pristine sha256  E3FC655A335E17A6FDD09A9B315291D0C8863180F0D801E5DD7433C9E56AFBD8
patched  sha256  FF658CE12E67D813037B68F54FA7DC0F63B7787641CFF8E095D83814E2704547
```

53 bytes are written across the four windows; **29 of them differ** from the original — the
rest already held the value being written. The full diff, straight out of
`tools\byte_diff.ps1`:

```
total differing bytes: 29
  @0x2DD6    orig=74  patched=EB                        .text   site 3, the branch byte
  @0x4C2F0   orig=55  patched=B8                        .text   site 2
  @0x4C2F1   orig=8D  patched=01                        .text   site 2
  @0x4C2F2   orig=AC  patched=00                        .text   site 2
  @0x4C2F3   orig=24  patched=00                        .text   site 2
  @0x4C2F4   orig=9C  patched=00                        .text   site 2
  @0x4C2F5   orig=F7  patched=C3                        .text   site 2
  @0x4FF40   orig=55  patched=31                        .text   site 1
  @0x4FF41   orig=8D  patched=C0                        .text   site 1
  @0x4FF42   orig=AC  patched=C3                        .text   site 1
  @0x38DB5C  orig=55  patched=52                        .rsrc   U -> R
  @0x38DB5E  orig=6E  patched=65                        .rsrc   n -> e
  @0x38DB60  orig=72  patched=67                        .rsrc   r -> g
  @0x38DB62  orig=65  patched=69                        .rsrc   e -> i
  @0x38DB64  orig=67  patched=73                        .rsrc   g -> s
  @0x38DB66  orig=69  patched=74                        .rsrc   i -> t
  @0x38DB68  orig=73  patched=65                        .rsrc   s -> e
  @0x38DB6A  orig=74  patched=72                        .rsrc   t -> r
  @0x38DB6E  orig=72  patched=64                        .rsrc   r -> d
  @0x38DB70  orig=65  patched=20                        .rsrc   e -> (space)
  @0x38DB72  orig=64  patched=56                        .rsrc   d -> V
  @0x38DB74  orig=20  patched=65                        .rsrc   (space) -> e
  @0x38DB76  orig=56  patched=72                        .rsrc   V -> r
  @0x38DB78  orig=65  patched=73                        .rsrc   e -> s
  @0x38DB7A  orig=72  patched=69                        .rsrc   r -> i
  @0x38DB7C  orig=73  patched=6F                        .rsrc   s -> o
  @0x38DB7E  orig=69  patched=6E                        .rsrc   i -> n
  @0x38DB80  orig=6F  patched=20                        .rsrc   o -> (space)
  @0x38DB82  orig=6E  patched=20                        .rsrc   n -> (space)
```

The three gaps in the `.rsrc` run are the characters that stayed put: the `e` at index 8 of
both strings, and the two UTF-16 high bytes and the terminator that are `00` on both sides.

Every patched byte matches the in-memory PoC that was proven live first — the disk patch is
that exact patch made permanent.

Reversibility is the strongest form of this proof: writing the four original signatures
back over the patched image reproduces the pristine sha256 **byte for byte**. The patch
provably touches nothing outside those four windows.

Applying sites 3 and 4 on top of an already-patched 2-site binary produces the same
`FF658CE1…` hash as patching all four from pristine, so the transition from an existing
install is exact.

**Dynamic (Frida, in-memory, before touching the file)**

- both sites patched, before/after bytes confirmed at runtime;
- 12 s after resume: **ALIVE**, `Responding=True`, main window
  `Internet Download Manager 6.43` — no trial suffix in the title;
- full top-level window enumeration for the PID: no trial nag, no fake-serial dialog, no
  "n days remaining" box. The only visible dialog is `Tip of the Day`, which is stock IDM
  behaviour on a fresh install and has nothing to do with licensing;
- live globals: `b95bd24=1`, `b95bd28=30`, `f968d00=0` — the healthy file-initial states;
- zero Application-log crash events (`1000`/`1001`/`1026`) across every run;
- `DDE Server Window` and the hidden drop-target window present — browser integration and
  the drag-drop target are alive, i.e. the patch did not break normal operation.

**Matcher**

- `exact`, `shape` (all four sites, across two sections), `already` and `dark` exercised
  against real and mutated files;
- idempotent: a second run reports `already patched` and writes nothing;
- restore: `uninstall.cmd` returns the file to the pristine hash.

---

## 9. Exit codes

| code | meaning |
|---|---|
| `0` | patched, already clean, fast-path confirmed, or `--dry-run` |
| `1` | not elevated |
| `2` | target missing, not a PE, or not an i386 image |
| `3` | `IDMan.exe` locked (IDM running) |
| `4` | **dark** — signature missing or ambiguous on this build; nothing written |
| `5` | verify / swap failure; file left on its original build |

State lives in `C:\ProgramData\IdmPatch\`:

- `IDMan.exe.orig` — pristine backup, hash-checked on every restore;
- `state.json` — fast-path (`lastGoodSha`), patched offsets, tier;
- `dark-notified.json` — at most one "unrecognised build" notice per build.

---

## 10. Limits

- **An IDM update reverts the patch.** IDM ships a new signed `IDMan.exe`; the gate comes
  back until `patch-now.cmd` is run again. Manual mode by design — no task, no watcher.
- **A build whose signatures moved or duplicated will be refused.** That is a deliberate
  refusal, not a failure: this analysis covers the build in §1 and refuses to guess about
  anything else.
- **The master verdict and the fatal-message switch are untouched.** If a state were ever
  reached where runtime re-checks evaluate `0x7F2DBF` against a blocking verdict, those
  paths still behave exactly as shipped. On the verified build they are not reached — the
  startup check returns before any serial is read, so there is no serial state for a later
  re-check to act on.
- **No serial is ever written.** This patch does not make IDM *believe* it is registered; it
  makes the startup check *report* clean. Nothing is added to the registry, nothing is
  sent to any server, and the validator/crypto code is left fully intact and unreachable
  from startup.
- **The About dialog reads registered; the program does not think it is.** Sites 3 and 4 are
  display-only, and nothing that inspects actual license state reads what they change:
  `0x77BD24` still reads `1` on a trial build, `0x95BD28` still reads `30`, and the HKLM
  licensee value is still absent. Only the two strings the dialog paints are different.
  Any runtime re-check that compares real state behaves exactly as it did before.
