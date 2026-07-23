# Android APK Capture MVP Tasks

## Task 1: Package identity consistency

**Acceptance criteria:**
- [x] CMake generates `org.renderdoc.sanqicapture.<abi>.apk`.
- [x] Runtime lookup, manifest package, Java package, and package scripts use the same base.
- [x] A runnable static check rejects future identity drift.

**Verification:** Run the static check and inspect CMake configure output.

**Dependencies:** None.

**Files likely touched:** `renderdoccmd/CMakeLists.txt`, package scripts, one small check script.

## Task 2: Standalone Android build and stage

**Acceptance criteria:**
- [x] One Windows command configures/builds both ARM ABIs without rebuilding the Windows solution.
- [x] SDK/NDK/JDK paths are validated with actionable messages.
- [x] Signed APKs are copied to `x64/Development/plugins/android/`.

**Verification:** Run the command; inspect the APK with `aapt dump badging` and archive listing.

**Dependencies:** Task 1.

**Files likely touched:** one build script plus existing Android CMake only if build evidence requires it.

## Task 3: Desktop artifact discovery

**Acceptance criteria:**
- [x] SqCap resolves ADB and both ABI APK filenames from its normal app-folder search.
- [x] Missing artifacts produce the existing specific `AndroidAPKFolderNotFound` error.

**Verification:** Run host-side discovery checks with and without the staged APK.

**Dependencies:** Task 2.

**Files likely touched:** `renderdoc/android/android.cpp`, `renderdoc/android/android_tools.cpp` only if existing discovery fails.

## Task 4: Launch state and diagnostics

**Acceptance criteria:**
- [ ] ADB authorization, layer configuration, process exit, and connection timeout are distinguishable
      on a connected device. Static parsing and host unit checks are complete.
- [ ] Existing disconnect cleanup remains intact and failure reporting does not clear a later
      successful launch's settings.

**Verification:** Static command-result tests plus device failure-path checks when connected.

**Current evidence:** `[android]` unit tests pass 140 assertions; the no-device preflight path exits
with the documented code 2 and a direct corrective message.

**Dependencies:** Task 3.

**Files likely touched:** `renderdoc/android/android.cpp`, existing Android tests/checks.

## Task 5: Remote context smoke test

**Acceptance criteria:**
- [ ] Authorized device is listed.
- [ ] Matching server APK installs/starts and PC connects to the remote server.

**Verification:** ADB package/process/port-forward evidence and SqCap log.

**Dependencies:** Tasks 2-4 and a connected device.

## Task 6: End-to-end frame capture

**Acceptance criteria:**
- [ ] Debuggable Vulkan target launches and becomes capturable.
- [ ] One frame produces an RDC transferred to PC.
- [ ] SqCap desktop replay opens the RDC successfully.
- [x] Existing PC build and replay smoke test remain green.

**Verification:** Device/host logs, RDC file, replay exit/result, and Windows regression build.

**Dependencies:** Task 5 and a test APK.
