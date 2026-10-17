# reapower

Reversing notes and tooling for software worth taking apart.

| folder | what |
|---|---|
| [`ServBay/`](ServBay/README.md) | ServBay (Windows local dev stack) — IL-level entitlement unlock + self-relocating auto-patcher. .NET 9, one 17 MB assembly, zero metadata edits. |
| [`TablePlus/`](TablePlus/README.md) | TablePlus (database client) — two in-place TINY-IL rewrites behind a tiered matcher (exact / shape / fuzzy / dark) so the patch survives WinSparkle updates. .NET Framework 4.8, 40,072 methods, 18 bytes changed. |
| [`Herd/`](Herd/README.md) | Herd (Windows local dev stack) — nothing to decompile: the main bundle is V8 cached-data bytecode, so the Pro accessors get shadowed at runtime and the 7.7 KB shim is baked into `app.asar`. Electron 44, 19,517 files, 1 changed. |

Each folder has its own README with the full analysis: how the target protects itself,
what was actually found under the surface, the exact patch, and how it was verified.
