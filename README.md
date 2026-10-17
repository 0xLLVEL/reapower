# reapower

Reversing notes and tooling for software worth taking apart.

| folder | what |
|---|---|
| [`ServBay/`](ServBay/README.md) | ServBay (Windows local dev stack) — IL-level entitlement unlock + self-relocating auto-patcher. .NET 9, one 17 MB assembly, zero metadata edits. |

Each folder has its own README with the full analysis: how the target protects itself,
what was actually found in the IL, the exact byte-level patch, and how it was verified.
