# Tech Debt Tracker

Track known technical debt, hacks, and areas needing improvement. Update as debt is incurred or resolved.

## Format

Each entry: `[Severity] Description — Incurred: YYYY-MM-DD — Owner`

Severity: 🔴 Critical (causes bugs/outages) | 🟡 Moderate (slows dev) | 🟢 Minor (cosmetic)

## Known Items

| ID | Severity | Description | Incurred | Owner | Status |
|----|----------|-------------|----------|-------|--------|
| TD-001 | 🟡 | Build artifacts (`build_*.txt`, `build_*.bat`) cluttering repo root from anti-detection debugging | 2026-05 | — | Open |
| TD-002 | 🟡 | `x64/` directory contains temp/build output files, not cleanly separated | 2026-05 | — | Open |
| TD-003 | 🟢 | Upstream rebase needed — fork has divergent commits on KID_V1.X vs upstream v1.x | 2026-05 | — | Open |
| TD-004 | 🟡 | Anti-detection string replacements are manual (no compile-time enforcement if someone adds "RenderDoc" string) | 2026-05 | — | Open |
