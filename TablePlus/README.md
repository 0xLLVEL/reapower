# TablePlus — License Gate Analysis & Patch (Windows x64)

Target: `C:\Program Files\TablePlus\TablePlus.exe`
Build analysed: **26.10.16** — 156,425,792 bytes
SHA-256 (original): `03A5BAD42EC539630E9B293409BCF7ABCF993CAC85EBF28C64120C0576A37A24`
SHA-256 (after patch): `9F4F5788C18264BEF75F35FC2FC3E60D404EB2171B96AEC6BA4603A4464B11D4`

---

## 1. Binary shape

| Property | Value |
|---|---|
| Format | PE32+, x86_64, **managed** (CLI header at RVA `0x2000`) |
| Sections | 2 (`.text` 155 MB, `.rsrc`) |
| Runtime | .NET Framework 4.8.1 (WPF) — `TablePlus.exe.config` |
| Metadata root | RVA `0x2DB5B8`, size `0x399AFC` (3.7 MB), file offset `0x2D97B8` |
| MVID | `07fa9fdd-79fa-425f-8f64-13c9447eac5b` |
| TypeDef / MethodDef | 4,607 / **40,072** |
| Entry point | `0x060039E2` |
| Dependencies | merged into one assembly (AvalonEdit, Markdig, CSRedis, DuckDB.NET, LiveCharts, CsvHelper, … still present in the IL) |

Executable IL ends around file offset 44 MB; the remaining ≈110 MB is
ManifestResource. That is why REA static analysis cannot consume the whole file
(snapshot cap 128 MB / 64 MB) — a *derived artifact* is used instead: a 48 MiB
prefix whose bytes are identical to the original, with only the section table
adjusted so it stays well-formed. Every byte coordinate in this document refers
to the **original** file.

> Limitation note: on the derived artifact REA reports member `rva`/`file_offset`
> with a fixed shift (≈54 bytes). Method identity is still guaranteed because the
> `il_sha256` REA reports matches the IL at the offsets this patch uses
> **byte-for-byte** (verified for 8 methods). The canonical coordinates are the
> ones read from the metadata tables directly, not those fields.

---

## 2. License surface

All inside namespace `TablePlus.Source`, typedef `LicenseService` = `0x02000633`.

| Field | Token | Note |
|---|---|---|
| `isValidLicense` | `0x040013F6` | bool, private — the single source of truth |
| `license` | `0x040013F7` | instance of `TablePlus.Source.Models.License` |
| `IsExpireChecked` | `0x040013F8` | public bool |

| Method | Token | Original IL | Role |
|---|---|---|---|
| `IsLicensed` | `0x06003E08` | `02 7B F6 13 00 04 2A` | the single predicate, read from **17 sites** |
| `get_DayBeforeExpiration` | `0x06003E06` | `02 7B F7 13 00 04 6F 35 43 00 06 2A` | days left before updates expire |
| `Check` | `0x06003E0E` | 108 B, fat | loads the license JSON, checks the device ID ("Invalid ID") → sets `isValidLicense` |
| `Remove` | `0x06003E0D` | 61 B | removes the key, `isValidLicense = false` |
| `GetSign` / `GetEmail` / `UpdateAvailableUtils` | `…E09/E0A/E0B` | 31 B | reads `license.X ?? ""` |
| `Identifier` / `BaseId` / `BiosId` / `GetMacAdress` | — | — | machine fingerprint (WMI `Win32_BaseBoard`, `Win32_BIOS`) |

The `TablePlus.Source.Models.License` model (`0x020006A5`) stores the license as
JSON with 4 keys: `deviceID`, `updatesAvailableUntil`, `email`, `sign`
(`Load` `0x06004342`, `Save` `0x06004343`, `IsInitialized` `0x06004340`).

**Callers of `IsLicensed` (17)** — this is why one patch is enough:

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

`WorkspaceWindow::UpdatePropertiesBasedOnLicense` (`0x060056EA`):

```
if (!IsLicensed)                  -> ShowTrialButton      (0x060056EB)
else if (DayBeforeExpiration >= 0)-> HideTrialButton      (0x060056EC)
else if (Setting.X)               -> HideTrialButton
else                              -> ShowTrialButton
```

So the "licensed and not expired" state = `IsLicensed == true` **and**
`DayBeforeExpiration >= 0`. Both are patched.

---

## 3. The patch

In place on the method bodies, TINY headers, metadata tables **untouched**.

### Gate 1 — `LicenseService::IsLicensed` (`0x06003E08`)

| | |
|---|---|
| RVA | `0x000F8690` |
| Header (file) | `0xF6890` = `0x1E` (TINY, ilSize 7) |
| IL (file) | `0xF6891` |
| Before | `02 7B F6 13 00 04 2A` → `ldarg.0; ldfld isValidLicense; ret` |
| After | `17 2A` → `ldc.i4.1; ret` |

```
0xF6890:  1E 02 7B F6 13 00 04 2A     ->  0A 17 2A 00 00 00 00 00
```
The 5 surplus bytes are zero-filled. New header `0x0A` = TINY, ilSize 2.

### Gate 2 — `LicenseService::get_DayBeforeExpiration` (`0x06003E06`)

| | |
|---|---|
| RVA | `0x000F8675` |
| Header (file) | `0xF6875` = `0x32` (TINY, ilSize 12) |
| IL (file) | `0xF6876` |
| Before | `02 7B F7 13 00 04 6F 35 43 00 06 2A` |
| After | `20 0F 27 00 00 2A` → `ldc.i4 9999; ret` |

```
0xF6875:  32 02 7B F7 13 00 04 6F 35 43 00 06 2A  ->  1A 20 0F 27 00 00 2A 00 00 00 00 00 00
```

**Total bytes changed: 18** out of 156,425,792 — all inside two method bodies
(`0xF6875..0xF6881`, `0xF6890..0xF6897`). Not a single byte outside that range.

---

## 4. Verification

`TablePlusPatch.ps1` recognises each site by **method name in the metadata**, then
matches the SHA-256 of the IL currently present:

| Site | SHA-256 of original IL | SHA-256 of patched IL |
|---|---|---|
| `IsLicensed` | `f951d7b7ac40545b9d0d4a899003d5314fd99b8951f4ba22e9f94f4386ca03aa` | `3e652f9ec0ddcdd64c52c9cba261a1f70bba3ffa41ff4296d6eba45e6514b378` |
| `get_DayBeforeExpiration` | `0a8887382ffd440d314c339ecf298d6c1d552318e806e459f6c393a76383271f` | `f9b9a361ce548af8ab6c7e145721799dc9255eb732d964832d92b9034b85496a` |

- Unknown IL → the site is **not touched**, it is reported. No blind patching.
- Already patched → skipped. Idempotent: second run = 0 changes.

Re-read by REA from the patched binary:

```
0x06003e08  IsLicensed  ->bool  il=2  hdr=tiny  ops: ldc.i4.1x1 retx1
0x06003e06  get_DayBeforeExpiration ->i4  il=6  hdr=tiny  ops: ldc.i4x1 retx1
                                      anchors: 0:ldc.i4(9999)
0x06003e0d  Remove      ->void  il=61  (unchanged, same shape)
0x06003e0e  Check       ->void  il=108 (unchanged, same shape)
```

---

## 5. Install / remove

```
install.cmd      # request UAC -> copy the engine to C:\ProgramData\TablePlusPatch,
                 # patch now, register the scheduled task
uninstall.cmd    # remove the task, restore the original exe from backup
```

Manual, one-shot:

```powershell
# run PowerShell as Administrator
.\TablePlusPatch.ps1 -Target "C:\Program Files\TablePlus\TablePlus.exe" -DryRun
.\TablePlusPatch.ps1 -Target "C:\Program Files\TablePlus\TablePlus.exe"
```

`TablePlusPatch.ps1 -Restore` restores from `TablePlus.exe.bak`.

### Resilience against updates

TablePlus uses **WinSparkle** (`x64\WinSparkle.dll`); an update overwrites
`TablePlus.exe` and wipes the patch. `install.cmd` registers the scheduled task
**"TablePlus License Patch"** — at logon + every 10 minutes, `RunLevel Highest`,
waiting for the `TablePlus` process to exit (max 120 s) before writing.

Each site is decided in order, so any update is still handled:

| State after update | Action | Tier |
|---|---|---|
| IL still byte-identical | patch | `exact` |
| recompiled, field token shifted but the getter shape is the same | patch | `shape` |
| declaring type renamed / moved namespace | find by method name + shape, then patch | `fuzzy` |
| the gate was genuinely rewritten | **not touched**, recorded, one notification | `dark` |
| already patched | skipped (idempotent) | — |

A "dark" site is never patched blind: better TablePlus falls back to free mode
than have the exe corrupted. When that happens a MessageBox appears once per build
(deduped via `state.json`, so it does not nag every 10 minutes) and the line lands
in `tableplus-patch.log`.

The backup also follows versions: `backup\TablePlus.exe.orig` is refreshed **only
when the file on disk is still a vendor build**, and every version is recorded in
`versions.txt`. So a rollback always targets the build that is actually installed,
never an older one.

Verified with update simulations:

```
normal update                      -> exact  : 2 patched
recompile, field token shifted     -> shape  : 2 patched   (old engine: 1, the other went silently dark)
gate rewritten                     -> dark   : 0 patched, one notification, next run silent
declaring type renamed             -> fuzzy  : 2 patched
```

**After an update, there is nothing to do.** If TablePlus rewrites the gate into
an unrecognisable shape you get told about it — then `TablePlusPatch.ps1 -DryRun`
shows you the new IL so it can be re-derived.

---

## 6. Files

| File | Contents |
|---|---|
| `TablePlusPatch.ps1` | patch engine (find-by-name, SHA verification, in-place patch) |
| `TPCli.cs` | PE + CLI metadata reader and TINY-IL writer |
| `make_rea_artifact.ps1` | builds the <64 MiB derived artifact for REA (byte-identical prefix) |
| `Pe.cs` | PE header / metadata stream dump and byte search |
| `dump_il.ps1` | raw IL dumper |
| `install.cmd` / `Install-TablePlusPatch.ps1` | installer + scheduled task |
| `uninstall.cmd` | removal + restore |
| `tp_methods.tsv` | 40,072 rows: token, row, `Type::Method`, RVA, ilSize, ilOffset |

---

## 7. REA evidence

| Artifact | SHA-256 | Evidence |
|---|---|---|
| `TablePlus.rea.exe` (original, prefix) | `e17fc7c265b911c58f2338ac98030978f4afae79ce57f426ef0b2116a6700bb6` | artifact `ev_3f78cbf7…`, members `ev_a40adb67…`, methods `ev_376d8faa…` |
| `TablePlus.patched.rea.exe` | `9228cb2407e7da723bda470e60e6eb2491149bb607b0dde51bb0b63f069a4405` | members `ev_57b9193e…` |

---

## 8. Limits

- This patch touches the **client gate**. If TablePlus verifies a license against
  the server for certain operations (online activation/registration:
  `SourceService::CheckLicenseOnline`, `RegisterLicense`, `UnregisterLicense`),
  those network operations are left as-is — only the local gate is removed.
- Not yet tested with the GUI running. A backup is always taken before writing;
  `uninstall.cmd` returns the original exe intact.
- TablePlus binaries are not included in this repository.
