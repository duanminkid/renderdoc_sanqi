# Implementation Plan: Android APK Capture MVP

## Overview

Restore the existing Android remote-capture path as a reproducible SqCap feature. The work starts by
making the helper APK identity consistent, then establishes a standalone arm64 Android build and
stages the output where the Windows UI already looks for Android plugins. Runtime changes are limited
to explicit diagnostics or state cleanup proven necessary by build/device checks.

## Architecture Decisions

- Reuse the existing `adb://` remote protocol and capture dialog; do not create a second launcher.
- Use Android 10+ native GPU debug layers for the MVP and keep JDWP only as the existing fallback.
- Use `org.renderdoc.sanqicapture.<abi>` consistently because this is the current runtime contract.
- Build/stage `arm64-v8a` first; keep package naming and scripts ABI-generic for arm32.
- Treat root/Zygisk injection as a separate future slice because the checked-in module is incomplete.

## Dependency Graph

Package identity consistency
  -> signed helper APK build
    -> desktop artifact staging
      -> remote server install/start
        -> target package launch and target-control connection
          -> frame capture transfer and desktop replay

## Task List

### Phase 1: Buildable helper APK

- [x] Task 1: Unify Android helper package identity and artifact lookup.
- [x] Task 2: Add a standalone Windows Android build/stage entry point for both ARM ABIs.

### Checkpoint: Helper artifact

- [x] CMake configure and both ARM builds succeed.
- [x] `aapt dump badging` reports the expected package and debuggable/native ABI metadata.
- [x] APK contains the expected capture-layer and server libraries.

### Phase 2: Desktop integration

- [x] Task 3: Stage APK/platform-tools under the desktop output and verify discovery.
- [ ] Task 4: Verify Android launch failures are actionable without changing global-setting ownership.

### Checkpoint: Host integration

- [x] Development x64 build succeeds.
- [x] Android package/static consistency checks pass.
- [x] Existing Windows RDC replay smoke test exits successfully.

### Phase 3: Device validation

- [ ] Task 5: Install/start the server and establish an Android remote context.
- [ ] Task 6: Launch a debuggable Vulkan APK, capture one frame, transfer the RDC, and replay it.

### Checkpoint: Complete

- [ ] All spec success criteria have direct evidence.
- [ ] Code review finds no unresolved P0/P1 issue.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Configured NDK r14b is incompatible with current CMake/source | High | Resolved for the MVP: both ARM ABIs build with the installed r14b toolchain. |
| Android build-tools 35 rejects Java 7 source flags | Medium | Resolved for the MVP by using the installed JDK 8/build-tools 26.0.1/android-23 toolchain. |
| SqCap string stripping changes Android runtime identifiers | High | Validate identifiers inside the final APK and keep package/layer names out of post-build binary rewriting. |
| No authorized device is connected | High for E2E | Finish build/static/host checks now; require a connected device before claiming completion. |
| Commercial APK is not debuggable | High | Keep it outside MVP; design root/Zygisk separately when explicitly requested. |

## Open Questions

- Which physical device/API level and target package will be used for the final device test?
- Which debuggable Vulkan APK will be used for the first end-to-end capture?
