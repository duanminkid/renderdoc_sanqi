# Product Specs Index

Product specifications and feature requirements for SanQi Capture.

## Current Specs

- [Android APK Capture MVP](android-apk-capture-mvp.md) — Draft; Android 10+ debuggable APK,
  Vulkan-first remote capture workflow.
- [Generic Steam Capture Launch](steam-platform-capture.md) - In progress; manifest-derived AppID,
  normal Steam launch, and install-root-scoped process discovery.

## Spec Template

```markdown
# Feature: [Name]

**Status**: draft | in-progress | completed
**Created**: YYYY-MM-DD
**Author**: [name]

## Problem Statement
What user problem does this solve?

## Requirements
- [ ] Requirement 1
- [ ] Requirement 2

## Success Criteria
How do we know this is done?
```

## Upstream RenderDoc Features

This fork inherits all features from upstream RenderDoc:
- Frame capture and replay for Vulkan, D3D11, D3D12, OpenGL, GLES
- Shader debugging (SPIR-V, DXIL, DXBC)
- Texture viewer, mesh viewer, pipeline state viewer
- Python scripting API
- Remote capture server

For upstream feature documentation, see:
- https://renderdoc.org/docs/
- `docs/` (Sphinx RST documentation)
