# reapower

Reversing notes and tooling for software worth taking apart.

| folder | what |
|---|---|
| [`ServBay/`](ServBay/README.md) | ServBay (Windows local dev stack) — IL-level entitlement unlock + self-relocating auto-patcher. .NET 9, one 17 MB assembly, zero metadata edits. |
| [`TablePlus/`](TablePlus/README.md) | TablePlus (database client) — two in-place TINY-IL rewrites behind a tiered matcher (exact / shape / fuzzy / dark) so the patch survives WinSparkle updates. .NET Framework 4.8, 40,072 methods, 18 bytes changed. |
| [`Herd/`](Herd/README.md) | Herd (Windows local dev stack) — nothing to decompile: the main bundle is V8 cached-data bytecode, so the Pro accessors get shadowed at runtime and the 7.7 KB shim is baked into `app.asar`. Electron 44, 19,517 files, 1 changed. |
| [`MampPro/`](MampPro/README.md) | MAMP PRO (Windows local dev stack) — four FAT-IL rewrites (startup gate, bought flag, both serial-dialog triggers) behind the same tiered matcher plus a module-wide `newobj` ctor gate. .NET 6, 5,490 methods, 1,353 bytes changed. |
| [`Idm/`](Idm/README.md) | Internet Download Manager (Windows download manager) — two native prologue rewrites (startup validator → status 0, nag/exit gate → continue) behind a section-scanning signature matcher, with the ~100-caller master verdict deliberately left alone. x86 PE, 9 bytes changed. |
| [`Lunar/`](Lunar/README.md) | Lunar Client (Electron game launcher) — two stages. (1) Blows the Electron asar-integrity fuse off and neutralises the embedded Overwolf `owepm` validator (five OR-ed checks plus both catch paths) so `resources\app.asar` becomes writable: 8 bytes of a 235 MB x64 PE. (2) Two net-zero-length spans inside `main.js` plus a fake `accounts.json` entry remove the launcher's Minecraft-ownership gate: the launcher boots as a non-existent account and shows `LAUNCH GAME`. Electron 42.7.1. |
| [`Madium/`](Madium/README.md) | Madium (Roblox executor, Tauri/Rust desktop app) — the entitlement is decided server-side, so the client is not tricked: the pinned Ed25519 verifying key is replaced with one you control and the auth host is redirected to a local endpoint that signs its own verdicts over the recovered canonical JSON form. Six gate sites neutralised alongside. x64 PE, 62 bytes changed. |

Each folder has its own README with the full analysis: how the target protects itself,
what was actually found under the surface, the exact patch, and how it was verified.
