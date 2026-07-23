# Design Docs Index

Design documents capture architectural decisions, trade-off analysis, and accepted patterns for this project.

## Core Design Documents

*None yet. Create the first design doc when you make a significant architectural decision.*

## Template

When creating a new design doc, follow this structure:

```markdown
# Title: [Decision]

**Date**: YYYY-MM-DD
**Status**: proposed | accepted | superseded
**Author**: [name]

## Context
What problem are we solving? What constraints apply?

## Decision
What did we choose? Be specific.

## Alternatives Considered
- Option A: ... (rejected because ...)
- Option B: ... (rejected because ...)

## Consequences
What gets easier? What gets harder? What follow-up work is needed?
```

## Key Design Decisions (Known from Code)

| Decision | Rationale | Location |
|----------|-----------|----------|
| Fork RenderDoc (not rewrite) | Leverage mature graphics debugging engine | — |
| Brand all strings → SqCapLib | Anti-detection requirement | `stealth_remap.h`, `string_obfuscation.h` |
| Version.dll proxy injection | Stealth injection without CreateRemoteThread | `win32_stealth.h` |
| VS2019 v142 toolset | Compatibility with target environment | All .vcxproj files |
| Qt5 for GUI | Upstream RenderDoc uses Qt5 | `qrenderdoc/` |
