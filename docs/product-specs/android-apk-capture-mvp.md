# Feature: Android APK Capture MVP

**Status**: in-progress
**Created**: 2026-07-17
**Target host**: Windows x64 SqCap

## Objective

Provide a PC-like Android capture workflow from SqCap: discover a connected Android device, deploy
and start the matching capture server APK, browse and launch a target package, wait for target
control to connect, show the application as capturable, trigger a frame capture, transfer the RDC to
the host, and replay it in the desktop UI.

The first delivery restores and verifies the existing upstream Android path instead of introducing a
second injection architecture.

## MVP Scope

- Android 10 or newer physical device connected through ADB.
- `arm64-v8a` server APK first; `armeabi-v7a` remains buildable when the device needs it.
- A target APK whose manifest enables `android:debuggable="true"`.
- Vulkan capture is the primary acceptance path. OpenGL ES is accepted only after the Vulkan path
  works and the existing GLES layer passes the same checks.
- No root, Magisk, Zygisk, APK resigning, or system partition modification.
- The desktop UX reuses the existing remote-context and capture dialog rather than adding another
  Android-only launcher.

## Existing Architecture to Reuse

- `renderdoc/android/android.cpp`: device server install/start, package launch, GPU debug-layer
  configuration, port forwarding, target-control wait, and capture transport.
- `renderdoc/android/android_tools.cpp`: Android SDK/ADB discovery and command execution.
- `renderdoccmd/android/`: Android server APK manifest, Java loader, and native server executable.
- `renderdoc/driver/vulkan/vk_layer_android.cpp`: Android Vulkan layer entry points.
- `qrenderdoc`: existing remote context, package browser, capture controls, and replay UI.

## Required Changes

1. Use one post-processing-safe package identity everywhere:
   `com.sqcap.capture.sqcaptur.<abi>`.
2. Add a reproducible Windows Android build command using the configured SDK, NDK, JDK, CMake, and
   Ninja without requiring the full Windows installer build.
3. Stage the generated APKs and required ADB files under the desktop output's
   `plugins/android/` directory so `InstallRenderDocServer()` can find them.
4. Preserve the configured Vulkan layer name `VK_LAYER_MICROSOFT_SystemLoad` and verify the APK
   actually exports the corresponding Android layer library.
5. Surface actionable errors for missing ADB authorization, missing server APK, unsupported ABI,
   non-debuggable targets, failed GPU-layer settings, process exit, and target-control timeout.
6. Keep Android changes isolated from Windows launch/injection selection so PC YuanShen and Steam
   capture behavior is unchanged.

## Tech Stack

- C++/CMake/Ninja for Android native libraries and `sanqicapture` server.
- Android SDK build-tools (`aapt`, `d8`, `zipalign`, `apksigner`).
- Android NDK Clang for `arm64-v8a` and optional `armeabi-v7a`.
- Java loader activity packaged as a debuggable helper APK.
- ADB remote protocol and Vulkan GPU debug layers.

## Commands

The validated standalone build command is:

```powershell
& "E:/work/sqcap_src/build_android_apk.ps1" -Abi all -HostConfiguration Development
```

On the current workstation this selects JDK 8, Android SDK build-tools 26.0.1/android-23, and NDK
r14b. Explicit path parameters are available when those defaults are installed elsewhere.

Host regression build:

```powershell
cmd /c "E:/work/sqcap_src/build_me.bat"
```

Device smoke checks:

```powershell
& "E:/work/sqcap_src/test_android_capture_prereqs.ps1"
& "E:/work/sqcap_src/test_android_capture_prereqs.ps1" -PackageName "com.example.game"
```

The preflight exits with code 2 for a missing, offline, unauthorized, or ambiguous device and emits
the exact corrective action. With a connected device it reports API level, ABI list, Vulkan feature
support, matching helper APK, and optional target package/debuggable/default-activity information.

## Project Structure

- Android runtime and orchestration: `renderdoc/android/`
- Android graphics hooks: `renderdoc/driver/vulkan/`, `renderdoc/driver/gl/`
- Server APK: `renderdoccmd/android/`, `renderdoccmd/CMakeLists.txt`
- Desktop UI: `qrenderdoc/`
- Build/package scripts: `renderdoc/util/buildscripts/scripts/`
- Generated artifacts: `build-android-*/bin/`, then staged to
  `x64/Development/plugins/android/`

## Code Style

Follow the repository C++ style and keep Android command construction explicit:

```cpp
Process::ProcessResult result =
    Android::adbExecCommand(deviceID, "shell getprop ro.build.version.sdk");
if(result.strStdout.trimmed().empty())
  return RDResult(ResultCode::AndroidABINotFound, "Couldn't query Android API level.");
```

No new dependency is introduced for the MVP.

## Testing Strategy

1. Static consistency check: package base, APK filename, manifest package, installer lookup, and
   runtime lookup all match for each ABI.
2. Android build: signed arm64 APK is produced and `aapt dump badging` reports the expected package,
   version, ABI libraries, debuggable application, and loader activity.
3. Host build: `Development|x64` succeeds and existing PC replay smoke test still exits with code 0.
4. Device smoke: device is detected and authorized; server APK installs, starts, and creates an ADB
   remote context.
5. End to end: a known debuggable Vulkan test APK launches, becomes capturable, produces one RDC,
   transfers it to the PC, and replays without corruption.
6. Failure checks: disconnected/unauthorized device and non-debuggable target report explicit errors
   instead of silently disconnecting.

## Current Verification Evidence

- `Development|x64` completed with exit code 0 on 2026-07-17.
- Previous Android artifacts used an identity that was changed by the Windows DLL post-build
  stripper. Those hashes are obsolete; both ABIs and device capture require validation after the
  identity fix.
- Android launch-output parsing passes 140 assertions across the two `[android]` unit-test cases,
  including successful launch, already-running warning, missing Activity, unauthorized device, and
  non-zero adb exit without output.
- The device preflight script passes PowerShell syntax validation and currently exits with the
  expected code 2 plus a direct "No Android device is connected" diagnostic.
- `sanqicapture.exe replay --loops 1 F:/1233.rdc` exits with code 0.
- The standard Windows payload retains TLS callbacks while the stealth payload has a null callback
  address, preserving the existing PC dual-payload contract.
- Device validation remains pending because `adb devices -l` currently lists no device.

## Boundaries

- Always: validate every ADB command result that controls the state transition; reset global GPU
  debug settings on disconnect; preserve ABI/package consistency; keep PC paths unchanged.
- Ask first: install or upgrade Android SDK/NDK/JDK components; enable root/Magisk; modify or resign a
  user's target APK; add third-party dependencies.
- Never: bypass an app's anti-cheat or security controls in the MVP; modify the Android system
  partition; claim device validation without an attached device and captured RDC.

## Success Criteria

- SqCap lists an authorized Android device and establishes its remote context.
- SqCap automatically installs/updates the matching arm64 server APK.
- A debuggable Vulkan target can be selected and launched from the existing capture dialog.
- The UI reports a live target-control connection and enables frame capture.
- One triggered frame produces an RDC that opens and replays in the SqCap desktop UI.
- Disconnect and all defined failure paths return the UI to a usable state.
- Windows PC build and an existing desktop RDC replay smoke test remain green.

## Open Question

Is the first real target a debuggable APK you control, or a non-debuggable commercial APK? The latter
requires a separate rooted-device/Zygisk design; the existing `zygisk_module` source is an unbuilt
prototype and is not part of this MVP.
