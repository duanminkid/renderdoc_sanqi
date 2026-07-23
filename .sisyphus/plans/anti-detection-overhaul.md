# Anti-Detection Overhaul - PC Frame Capture Tool

## TL;DR

> **Quick Summary**: Switch from SetWindowsHookEx+MinHook inline hook to Proxy DLL export forwarding (3DMigoto approach), eliminate all detection surfaces, enable stable frame capture in Genshin Impact.
> **Deliverables**: d3d11_proxy.dll (<15MB, zero fingerprints), stable Genshin capture, updated UI tool
> **Effort**: Large | **Waves**: 4 | **Critical Path**: T1->T6->T9->F1-F4

---

## Context

Transform RenderDoc fork into frame capture tool for Genshin Impact without anti-cheat detection. Current: injection works but game crashes (MinHook modifies d3d11.dll .text, detected by HoYoKProtect CRC). Key insight from Metis: proxy DLL export forwarding code ALREADY EXISTS in version_proxy.cpp, no rewrite needed.

---

## Work Objectives

### Must Have
- Proxy DLL in Genshin without crash
- No system DLL .text modification
- No extra processes/threads at load time
- No named kernel objects
- DLL < 15MB, zero renderdoc/sanqi/system_load fingerprints

### Must NOT Have
- DO NOT rewrite existing proxy export forwarding in d3d11_hooks.cpp
- DO NOT add new third-party dependencies or kernel countermeasures
- DO NOT modify SetWindowsHookEx injection path (keep as fallback)
- DO NOT include Android/mobile tasks
- DO NOT use UPX/PE packers

---

## Verification Strategy
- No automated tests. Agent-executed QA via bash (strings.exe, dir, MSBuild)
- Evidence: .sisyphus/evidence/task-{N}-{scenario-slug}.{ext}

---

## Execution Strategy

```
Wave 1: Task 1 (validate proxy viability) [GATE CHECK]
Wave 2: Tasks 2-6 (core fixes, parallel)
Wave 3: Tasks 7-9 (deep cleanup, parallel)
Wave FINAL: F1-F4 (review, parallel) -> user okay
```

| Task | Depends On | Blocks | Wave |
|------|-----------|--------|------|
| 1 | none | 2,3,4,5,6 | 1 |
| 2 | 1 | 8 | 2 |
| 3 | 1 | F1-F4 | 2 |
| 4 | 1 | F1-F4 | 2 |
| 5 | 1 | F1-F4 | 2 |
| 6 | 1 | 7,8,9 | 2 |
| 7 | 6 | 9 | 3 |
| 8 | 2,6 | F1-F4 | 3 |
| 9 | 6,7 | F1-F4 | 3 |

---

## TODOs

- [ ] 1. Verify Proxy DLL Viability in Genshin (GATE CHECK)

  **What to do**:
  - Build current code in Development config (existing proxy mode)
  - Copy d3d11_proxy.dll to Genshin game directory as d3d11.dll
  - Ask user to launch Genshin via official HoYoPlay launcher
  - Verify: (a) DLL file still exists (not deleted), (b) game loads, (c) no anti-cheat error
  - If DLL deleted: test alternative proxy targets (dxgi.dll, version.dll, xinput1_3.dll)
  - If crashes: check if HoYoKProtect verifies digital signatures
  - Record results in evidence file. ZERO code changes in this task.

  **Must NOT do**: Do NOT modify any source code. Just test and record.

  **Agent**: quick | **Skills**: [] | **Wave**: 1 (solo, GATE CHECK)
  **Blocks**: Tasks 2-6 | **Blocked By**: None

  **References**:
  - version_proxy.cpp:455-564 - DllMain proxy mode detection
  - version_proxy.cpp:145-205 - LazyInit loads real d3d11.dll from System32
  - version_proxy.cpp:213-268 - Proxy_D3D11CreateDevice export forwarding
  - Game dir: G:/game/miHoYo Launcher/games/Genshin Impact Game/

  **QA**: Copy DLL to game dir as d3d11.dll, ask user launch game, verify file persistence + game launch + no anti-cheat error. Evidence: task-1-proxy-viability.txt
  **Commit**: NO

- [ ] 2. Fix D3DKMT Stub Functions - Forward to Real d3d11.dll

  **What to do**:
  - In version_proxy.cpp, change 28 D3DKMT stubs (lines 354-381) from returning 0 to forwarding to real d3d11.dll
  - Follow existing pattern in Proxy_D3DKMTQueryAdapterInfo (line 384-388): LazyInit() + GetProcAddress + call
  - Each stub: add LazyInit(), GetProcAddress from g_hRealD3D11, forward call if available, else return 0

  **Must NOT do**: Do NOT change function signatures. Do NOT add new .def exports.

  **Agent**: quick | **Skills**: [] | **Wave**: 2 (parallel with T3-T6)
  **Blocks**: Task 8 | **Blocked By**: Task 1

  **References**:
  - version_proxy.cpp:354-397 - Current D3DKMT stubs (28 returning 0)
  - version_proxy.cpp:384-388 - Proxy_D3DKMTQueryAdapterInfo forwarding pattern to follow
  - version_proxy.cpp:78 - g_hRealD3D11 handle

  **QA**: Build succeeds. grep LazyInit count matches all D3DKMT functions. Evidence: task-2-build.txt
  **Commit**: YES - fix(d3dkmt): forward all stubs to real d3d11.dll

- [ ] 3. Disable Breakpad CrashHandler in Proxy Mode

  **What to do**:
  - First check: grep renderdoc.vcxproj for RENDERDOC_OFFICIAL_BUILD - if NOT defined, Breakpad already disabled via conditional compilation (crash_handler.h:27-30 requires it)
  - If Breakpad IS active: wrap RecreateCrashHandler() call in core.cpp:546 with if(!g_D3D11ProxyMode)
  - This prevents: kidcmd.exe subprocess, SystemLoadBreakpadServer named pipe, SL_CRASHHANDLE event

  **Must NOT do**: Do NOT remove Breakpad code entirely. Do NOT modify crash_handler.h.

  **Agent**: quick | **Skills**: [] | **Wave**: 2 (parallel)
  **Blocks**: F1-F4 | **Blocked By**: Task 1

  **References**:
  - core.cpp:544-546 - RecreateCrashHandler() call
  - core.cpp:53 - extern bool g_D3D11ProxyMode
  - crash_handler.h:27-34 - Conditional: RDOC_RELEASE + RDOC_WIN32 + RENDERDOC_OFFICIAL_BUILD
  - crash_handler.h:119-157 - CreateProcessW kidcmd.exe, named pipe, SL_CRASHHANDLE event
  - renderdoc.vcxproj:72,104 - Check preprocessor defines

  **QA**: Verify no kidcmd.exe process after DLL load. Verify RENDERDOC_OFFICIAL_BUILD not in vcxproj. Evidence: task-3-crashhandler.txt
  **Commit**: YES (if needed) - fix(crash): disable Breakpad in proxy mode

- [ ] 4. Eliminate File System Artifacts

  **What to do**:
  - In version_proxy.cpp DllMain (injection mode, line 511-531): wrap sl_diag.txt write with #ifdef DEBUG or remove entirely
  - In version_proxy.cpp InjectionInitThread (line 426-442): wrap sl_inject_ok.txt write with #ifdef DEBUG or remove
  - In version_proxy.cpp RawTrace function (line 33-72): disable entirely in Release builds or wrap with #ifdef DEBUG
  - The d3d11_proxy_trace.log is written IN THE GAME DIRECTORY - extremely detectable
  - In CaptureDialog.cpp TriggerGlobalHook: the sl_target.txt write can stay (only in injector process, not game)
  - Verify no other temp files are created in proxy mode

  **Must NOT do**: Do NOT remove the UI tools temp file writes (sl_target.txt is in injector process only).

  **Agent**: quick | **Skills**: [] | **Wave**: 2 (parallel)
  **Blocks**: F1-F4 | **Blocked By**: Task 1

  **References**:
  - version_proxy.cpp:33-72 - RawTrace writes d3d11_proxy_trace.log in game directory
  - version_proxy.cpp:511-531 - sl_diag.txt diagnostic logging
  - version_proxy.cpp:426-442 - InjectionInitThread writes sl_inject_ok.txt
  - CaptureDialog.cpp:293-430 - TriggerGlobalHook writes sl_target.txt (OK - injector only)

  **QA**: Build, launch game with proxy DLL. Verify no .log/.txt files created in game dir or TEMP dir by the proxy DLL. Evidence: task-4-files.txt
  **Commit**: YES - fix(stealth): remove file system artifacts in proxy/release mode

- [ ] 5. Eliminate InjectionInitThread in Proxy Mode

  **What to do**:
  - In version_proxy.cpp DllMain injection mode (line 540-545): wrap CreateThread(InjectionInitThread) with if(!g_D3D11ProxyMode) or remove
  - Actually, this thread is ONLY created in injection mode (inside the isTarget block at line 533-546)
  - But in proxy mode (isProxyMode=true, line 467-472) NO thread is created - verify this
  - If proxy mode path truly creates no threads, this task is just verification + documentation
  - Also check: does add_hooks() -> RegisterHooks() -> D3D11Hook::RegisterHooks() create any threads? (It shouldn't in proxy sideload case A)

  **Must NOT do**: Do NOT remove thread creation for injection mode (it is the fallback path).

  **Agent**: quick | **Skills**: [] | **Wave**: 2 (parallel)
  **Blocks**: F1-F4 | **Blocked By**: Task 1

  **References**:
  - version_proxy.cpp:467-472 - Proxy mode path (no thread creation - GOOD)
  - version_proxy.cpp:533-546 - Injection mode path (CreateThread InjectionInitThread)
  - version_proxy.cpp:426-442 - InjectionInitThread function
  - d3d11_hooks.cpp:87-92 - Proxy sideload case A: returns without hooks

  **QA**: Verify proxy mode code path creates zero threads. grep CreateThread in proxy mode path. Evidence: task-5-threads.txt
  **Commit**: YES (if changes needed) - fix(stealth): ensure zero thread creation in proxy mode

- [ ] 6. Switch to Release Build Configuration

  **What to do**:
  - Verify Release configuration exists and compiles in renderdoc.vcxproj
  - Build with: MSBuild renderdoc.vcxproj /p:Configuration=Release /p:Platform=x64
  - Verify output DLL size is < 15MB (current Development is 72MB, Release should be ~5-8MB)
  - Verify PostBuild event (strip_exports.py) runs correctly on Release output
  - Fix any Release-specific build issues (may need to update PostBuild paths)
  - Ensure DISABLE_RENDERDOC_EXPORTS and RDOC_BASE_NAME=system_load are in Release preprocessor defs
  - If Release config is missing or broken, create it based on Development + Optimization=MaxSpeed + no debug

  **Must NOT do**: Do NOT change Development config (keep it for debugging).

  **Agent**: unspecified-high | **Skills**: [] | **Wave**: 2 (parallel)
  **Blocks**: Tasks 7, 8, 9 | **Blocked By**: Task 1

  **References**:
  - renderdoc.vcxproj:57-60 - Release ItemDefinitionGroup (RELEASE preprocessor)
  - renderdoc.vcxproj:62-98 - Common ItemDefinitionGroup (shared settings)
  - renderdoc.vcxproj:100-104 - Development ItemDefinitionGroup
  - renderdoc.vcxproj:88-95 - PostBuild event (copy + strip_exports.py)
  - renderdoc.vcxproj:39 - WholeProgramOptimization=true
  - strip_exports.py - Binary fingerprint patcher

  **QA**: MSBuild Release succeeds. dir output DLL < 15MB. strip_exports.py produces >0 replacements. Evidence: task-6-release-build.txt
  **Commit**: YES - build: switch to Release configuration

- [ ] 7. Add /d1trimfile to Strip Source Paths from Binary

  **What to do**:
  - Add /d1trimfile:$(SolutionDir) to AdditionalOptions in renderdoc.vcxproj for Release config
  - This MSVC compiler flag strips the common prefix from __FILE__ macro expansions
  - Without it, every RDCLOG/RDCERR/RDCASSERT embeds full path like e:\workenderdoc_sanqienderdoc\...
  - With /d1trimfile, paths become relative like renderdoc\core\core.cpp
  - The strip_exports.py already replaces renderdoc\ and renderdoc/ patterns, so relative paths get cleaned too
  - Verify MSVC version supports this flag (VS2019+ required)
  - Build Release and verify no full source paths remain in binary

  **Must NOT do**: Do NOT add this to Development config (full paths useful for debugging).

  **Agent**: quick | **Skills**: [] | **Wave**: 3 (after T6)
  **Blocks**: Task 9 | **Blocked By**: Task 6

  **References**:
  - renderdoc.vcxproj:80 - AdditionalOptions (currently /w44062 /w44840)
  - renderdoc.vcxproj:72,104 - PreprocessorDefinitions for each config
  - strip_exports.py:18-20 - Already replaces renderdoc\ and renderdoc/ patterns
  - MSVC docs: /d1trimfile is undocumented but works in VS2019+

  **QA**: Build Release. strings.exe output.dll | findstr renderdoc_sanqi -> 0 results. strings.exe output.dll | findstr "e:\work" -> 0 results. Evidence: task-7-trimfile.txt
  **Commit**: YES - build: add /d1trimfile to strip source paths

- [ ] 8. Update UI Tool for Proxy DLL Deployment Mode

  **What to do**:
  - In CaptureDialog.cpp TriggerGlobalHook, add a new deployment mode alongside existing SetWindowsHookEx injection
  - Proxy deployment mode: copy d3d11_proxy.dll to game directory as d3d11.dll, then launch game normally
  - Add UI option or auto-detect: if target game has anti-cheat, use proxy mode; else use injection mode
  - Proxy mode steps: (1) copy DLL, (2) ShellExecuteW game exe, (3) wait, (4) optionally cleanup DLL after game exits
  - Keep SetWindowsHookEx path as fallback for games without DLL deletion
  - Handle edge case: game directory may require admin write permission
  - Handle edge case: game updates may delete the proxy DLL

  **Must NOT do**: Do NOT remove SetWindowsHookEx injection code. Do NOT hardcode game paths.

  **Agent**: unspecified-high | **Skills**: [] | **Wave**: 3 (after T2, T6)
  **Blocks**: F1-F4 | **Blocked By**: Tasks 2, 6

  **References**:
  - qrenderdoc/Windows/Dialogs/CaptureDialog.cpp:293-430 - TriggerGlobalHook current implementation
  - version_proxy.cpp:455-472 - Proxy mode detection in DllMain (isProxyMode = hModule == GetModuleHandleA("d3d11.dll"))
  - strip_exports.py - PostBuild creates d3d11_proxy.dll (clean version)
  - Game dir: G:/game/miHoYo Launcher/games/Genshin Impact Game/

  **QA**: Build UI tool. Launch UI, select game exe, click launch. Verify d3d11.dll copied to game dir. Verify game launches. Evidence: task-8-ui-deploy.txt
  **Commit**: YES - feat(ui): add proxy DLL deployment mode

- [ ] 9. Enhance strip_exports.py + Final Fingerprint Scan

  **What to do**:
  - Run comprehensive strings.exe scan on Release d3d11_proxy.dll to find ALL remaining fingerprints
  - Add any new patterns found to strip_exports.py replacements list
  - Known patterns that may need adding: source file relative paths, class names from RTTI (verify /GR- is effective), linker-generated strings, debug directory PDB path variations
  - Run final scan and document every remaining string that could identify this as RenderDoc
  - Verify the 3 remaining RDOC occurrences mentioned in session history are truly in .text (machine code, not string-scannable)
  - Check for: WrappedVulkan, WrappedMTL, IDXGIFactory wrapping class names
  - Check for: version strings like 1.41, FULL_VERSION_STRING
  - Check for: Baldur Karlsson, MIT License text (in .rdata from header comments? unlikely but check)

  **Must NOT do**: Do NOT try to eliminate ALL debug strings (diminishing returns). Focus on fixed-pattern signatures.

  **Agent**: quick | **Skills**: [] | **Wave**: 3 (after T6, T7)
  **Blocks**: F1-F4 | **Blocked By**: Tasks 6, 7

  **References**:
  - strip_exports.py - Current 64 replacement patterns
  - renderdoc.vcxproj:67,75 - RuntimeTypeInfo=false (RTTI disabled)
  - api/replay/version.h:96-105 - RENDERDOC_VERSION_MAJOR/MINOR, FULL_VERSION_STRING
  - d3d11_hooks.cpp:314 - HOOK_LOG with WrappedID3D11Device string
  - d3d11_device_wrap.cpp:4079, d3d11_context.cpp:1485,1500 - RDCDEBUG with WrappedID3D class names

  **QA**: strings.exe d3d11_proxy.dll | findstr /i "renderdoc RenderDoc RENDERDOC sanqi system_load RDOC WrappedID3D overlay" -> 0 results. Evidence: task-9-final-scan.txt
  **Commit**: YES - fix(stealth): enhance strip_exports.py + eliminate remaining fingerprints

---

## Final Verification Wave

- [ ] F1. Plan Compliance Audit (oracle) - verify Must Have/Must NOT Have
- [ ] F2. Code Quality Review (unspecified-high) - MSBuild Release + strings scan
- [ ] F3. Real Manual QA (unspecified-high) - deploy to Genshin, test launch+capture
- [ ] F4. Scope Fidelity Check (deep) - diff audit, no scope creep

---

## Commit Strategy

1. fix(d3dkmt): forward stubs to real d3d11.dll
2. fix(crash): disable Breakpad in proxy mode
3. fix(stealth): remove file system artifacts + InjectionInitThread
4. build: switch to Release config with /d1trimfile
5. feat(ui): add proxy DLL deployment mode
6. fix(stealth): enhance strip_exports.py + final scan

---

## Success Criteria
- DLL < 15MB
- strings scan = 0 renderdoc/sanqi/system_load hits
- Game runs 5+ minutes without crash
- Frame capture produces valid .rdc
