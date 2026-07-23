# Feature: Generic Steam Capture Launch

**Status**: single-entry Steam DXGI fix rebuilt; runtime Steam smoke test pending
**Created**: 2026-07-22
**Author**: Codex

## Objective

Launch Steam-managed Windows games through Steam's registered URI protocol and inject the capture
runtime into the newly-created game process without per-game names, paths, or AppIDs.

## Requirements

- Resolve the owning Steam app from `steamapps/appmanifest_*.acf` and the selected executable path.
- Launch with `steam://rungameid/<appid>` so Steam owns account, cloud, DLC, overlay, and launch state.
- Never create `steam_appid.txt`, forge Steam AppID environment variables, or directly launch a
  recognised Steam game's internal executable.
- Consider only new processes whose canonical executable path is inside the resolved install root.
- Mark the selected PID before loading the capture DLL. DllMain must only acknowledge the marker and
  return; hook registration runs later through an explicit remote entry point, outside loader lock.
- Treat inline DXGI hooks as usable only after their trampolines have actually been installed. Steam
  paths, process names, and Overlay module presence are not hook-state signals.
- Once the Steam DXGI inline transaction is active, do not publish the same factory hooks through
  IAT replacement or `GetProcAddress`; callers must continue through the detoured DXGI export.
- Prefer the exact executable selected by the user, except when a root-level bootstrapper has a
  larger same-named executable deeper in the install tree; otherwise use another executable in the
  same install root only after a bounded grace period for launcher-based games.
- Exclude Steam processes, crash reporters, updaters, and anti-cheat bootstrap processes.
- Preserve non-Steam launch behaviour.

## Tech Stack and Structure

- C++/Win32 implementation: `renderdoc/os/win32/win32_process.cpp`
- Capture connection: existing target-control protocol
- Build: `cmd /c "E:\work\sqcap_src\build_me.bat"`
- Release outputs: existing `x64/Release` and `Win32/Release` directories

## Code Style

```cpp
if(!ResolveSteamLaunch(app, steamLaunch))
  return SteamManifestResolutionError(app);

return LaunchSteamAndInject(steamLaunch, capturefile, opts);
```

Use early returns, existing `rdcstr`/`rdcarray` types, Win32 APIs already used by the process module,
and the repository `.clang-format` configuration.

## Testing Strategy

- Development x64 compile catches C++ and linkage regressions.
- A development assertion validates the minimal VDF value parser.
- Static checks verify no game-specific AppID or `steam_appid.txt` path remains.
- Runtime smoke tests cover Last Breath Demo and Hogwarts Legacy through normal Steam launch after
  the user authorises launching a game.
- Release x86/x64 builds update the existing output directories; no zip archive is required.

## Boundaries

- Always: preserve Steam launch semantics, scope PID matching to the resolved install root, restore
  existing non-Steam behaviour.
- Ask first: registry/global-hook activation or changes to Steam user configuration. This design does
  not use Global Hook.
- Never: bypass anti-cheat, write into game directories, invent a per-game fallback, or claim that
  protected processes are universally capturable.

## Success Criteria

- Last Breath Demo and Hogwarts Legacy use the same code path with manifest-derived AppIDs.
- Steam logs contain a normal launch record and no temporary AppID sidecar is created.
- A failed injection reports the attempted Steam app and target path without launching directly.
- Development and Release x86/x64 builds succeed in the existing output directories.

## Validation Record

- Development x64 build: passed.
- Release x64 and x86 builds: passed with whole-program optimization/LTCG disabled because MSVC
  14.43 reproducibly crashed during Vulkan link-time code generation. Per-file Release optimization
  remains enabled.
- Real manifest resolution inputs checked for Last Breath Demo (`4480000`) and Hogwarts Legacy
  (`990080`).
- Launcher regression check: Hogwarts' 289,792-byte root bootstrapper resolves to the
  450,656,768-byte `Phoenix/Binaries/Win64/HogwartsLegacy.exe`; Last Breath keeps its selected root
  executable unchanged.
- Steam Overlay regression: the normal Steam launch previously saved the Overlay detour as the real
  `CreateDXGIFactory` target, re-entered our hook, and returned `E_FAIL`. The revised flow defers hook
  registration until after DllMain, installs DXGI trampolines before publishing them as active, and
  reports synchronous registration failures to the injector.
- 2026-07-23 runtime evidence: Steam accepted `steam://rungameid/990080`, created the root launcher
  and target PID 7200, marker/injection completed, and the UI received success with ident 38920 in
  under one second. The target then repeatedly entered `CreateDXGIFactory_hook` before the first real
  call returned. The fix removes the duplicate Steam factory IAT path and keeps dynamic resolution on
  the MinHook-detoured export; x64/x86 Release outputs were rebuilt afterward.
- Global Hook is not used. The existing outputs were rebuilt in `x64/Release` and `Win32/Release`;
  no zip was produced.
- Runtime Steam launch/capture: intentionally not run automatically to avoid touching save/cloud
  state without explicit authorisation.

## Open Questions

- Runtime validation must confirm that synchronously loading the system DXGI module and installing
  the three factory trampolines remains compatible with Steam games that render through Vulkan or
  OpenGL. Registration failure is returned to the UI instead of being deferred.
- A game-local `dxgi.dll` proxy or second DXGI module is not covered by the single System32 DXGI
  trampoline transaction. Supporting mod/proxy chains requires per-module original pointers and is
  outside the normal unmodified Steam-game path.
