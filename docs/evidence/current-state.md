# Current State — Phase 0 Reconnaissance Snapshot

**Date**: 2026-05-25
**Branch**: KID_V1.X (forked from v1.x)
**Author**: zhongduanmin
**Project Type**: software (C/C++ graphics debugging tool)

## Project Identity

This is a **fork of RenderDoc** (MIT-licensed graphics debugger), rebranded as **"SanQi Capture" (SqCap)** with extensive anti-detection / stealth modifications. The original RenderDoc supports Vulkan, D3D11, D3D12, OpenGL, and GLES on Windows/Linux/Android.

**This fork focuses on**: Windows x64, D3D12/Vulkan capture, anti-detection obfuscation for use in game environments.

## 1. Directory Structure

```
sqcap_src/
├── renderdoc/          # Core DLL — capture + replay engine (~1326 source files)
│   ├── api/            # Public API (app/replay)
│   ├── driver/         # Graphics API drivers
│   │   ├── d3d11/      # D3D11 capture driver
│   │   ├── d3d12/      # D3D12 capture driver
│   │   ├── dx/         # DX shared headers (d3d12.h from SDK)
│   │   ├── dxgi/       # DXGI swapchain capture
│   │   ├── gl/         # OpenGL/GLES capture driver
│   │   ├── vulkan/     # Vulkan capture driver
│   │   ├── shaders/    # Shader processing (dxbc, dxil, spirv)
│   │   └── ihv/        # GPU vendor-specific (AMD, NV, Intel, ARM)
│   ├── core/           # Core data structures, settings, stealth_remap
│   ├── os/win32/       # Windows-specific: process injection, stealth, callstack
│   ├── replay/         # Replay engine (frame playback, shader debug)
│   ├── serialise/      # Capture file serialization (codecs)
│   ├── hooks/          # API hook definitions
│   ├── common/         # Common utilities
│   └── 3rdparty/       # Third-party libs (breakpad, glslang, pugixml, etc.)
├── qrenderdoc/         # Qt5 GUI application
│   ├── Code/           # C++ source
│   │   ├── Interface/  # Extension interface (QRDInterface, Extensions)
│   │   └── pyrenderdoc/ # Python bindings (SWIG)
│   ├── Widgets/        # Custom Qt widgets
│   ├── Windows/        # Window classes (Dialogs, PipelineState)
│   ├── Styles/         # Qt styles (RDStyle, RDTweakedNativeStyle)
│   └── 3rdparty/       # Qt/scintilla/pyside/python
├── renderdoccmd/       # CLI tool (capture + replay commands)
├── renderdocshim/      # Shim DLL for process injection
├── scripts/            # Helper scripts
│   ├── fix_cpp_classnames.py
│   └── strip_renderdoc_signatures.py
├── util/               # Build scripts, installer, test demos, SDK fix
├── docs/               # Sphinx user documentation
└── .github/workflows/  # CI (GitHub Actions)
```

## 2. Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | C++ (C++17 features used) |
| Build System | CMake + Visual Studio 2022 (v143 toolset; .vcxproj files use v142 but build scripts override) |
| Solution | `renderdoc.sln` (19 projects) |
| UI Framework | Qt 5 (qrenderdoc) |
| Scripting | Python 3 (build scripts, test infrastructure) |
| Python Bindings | SWIG (pyrenderdoc module) |
| Graphics APIs | Vulkan, D3D11, D3D12, DXGI, OpenGL, GLES |
| Shader Compilation | glslang (SPIR-V), DXBC/DXIL (DX shaders) |
| Crash Reporting | Google Breakpad |
| Serialization | Custom stream-based (renderdoc/serialise/) |
| Config Format | Clang-format (Chromium-based, 100 cols, 2-space indent) |

## 3. CI/CD

- **Provider**: GitHub Actions (`.github/workflows/ci.yml`)
- **Matrix**: Windows (x86/x64), Linux (x64), macOS, Android
- **Inactivity Lock**: Auto-closes stale issues/PRs (`inactivity-lock.yml`)

## 4. Container / Environment

- Dockerfiles exist only for CI build environments (`util/buildscripts/scripts/docker/`, `util/spirv-plugins/docker/`)
- No production containerization — this is a desktop tool

## 5. Entry Points

| Binary | Entry File | Purpose |
|--------|-----------|---------|
| `renderdoc.dll` | `renderdoc/api/app/` | Core capture/replay DLL |
| `qrenderdoc.exe` | `qrenderdoc/Code/qrenderdoc.cpp` | Qt GUI main window |
| `renderdoccmd.exe` | `renderdoccmd/renderdoccmd.cpp` (52KB) | CLI for capture/replay |
| `renderdocshim.dll` | `renderdocshim/renderdocshim.cpp` | Injection shim for stealth loading |

## 6. External Interfaces

- **In-application API**: `renderdoc/api/app/renderdoc_app.h` — programmatic capture control
- **Replay API**: `renderdoc/api/replay/renderdoc_replay.h` — capture file reading/analysis
- **Qt Extension Interface**: `qrenderdoc/Code/Interface/QRDInterface.h` — plugin API for UI
- **Python API**: SWIG-generated bindings in `qrenderdoc/Code/pyrenderdoc/`
- **Vulkan Layer**: JSON manifest for VK_LAYER_* implicit layer

## 7. Test Infrastructure

- **496 test .cpp files** across the tree
- In-tree unit tests: `renderdoc/common/*_tests.cpp`, `renderdoc/core/*_tests.cpp`, `renderdoc/serialise/*_tests.cpp`
- Graphics test demos: `renderdoc/util/test/demos/` (organized by API)
- Test framework: Catch2 (`renderdoc/3rdparty/catch/`)
- Python test infrastructure: `util/test/`

## 8. Core Business Domains (largest files)

| File | Lines | Domain |
|------|-------|--------|
| `driver/vulkan/vk_serialise.cpp` | 15,811 | Vulkan capture serialization |
| `driver/shaders/spirv/spirv_gen.cpp` | 14,239 | SPIR-V code generation |
| `driver/vulkan/wrappers/vk_cmd_funcs.cpp` | 10,516 | Vulkan command wrappers |
| `driver/shaders/dxil/dxil_debug.cpp` | 9,996 | DXIL shader debugging |
| `driver/d3d11/d3d11_context_wrap.cpp` | 8,167 | D3D11 context wrapping |
| `driver/vulkan/vk_shaderdebug.cpp` | 6,934 | Vulkan shader debugging |
| `driver/vulkan/vk_core.cpp` | 6,775 | Vulkan core driver |

## 9. Recent Development Direction (git log -30)

Latest commit: `4c227e347` — **"SanQi Capture: anti-detection overhaul with brand obfuscation and launch diagnostics"**

Key themes in recent history:
- **Anti-detection / stealth** — string obfuscation, VK layer name masking, stealth headers
- **Shader debugging** — SPIR-V/DXIL debugger improvements, atomic operations, GSM support
- **Bug fixes** — out-of-bounds reads, null pointer handling, descriptor state handling
- **Brand obfuscation** — stripping RENDERDOC strings, rebranding to SQCAPTLIB

## 10. Most Active Files (from latest commit diff)

The `4c227e347` commit touched ~50 files across:
- `qrenderdoc/` — UI strings rebranding
- `renderdoc/core/` — stealth_remap.h, settings.cpp, remote_server.cpp
- `renderdoc/os/win32/` — win32_process.cpp, win32_libentry.cpp, stealth headers
- `renderdoc/driver/d3d12/` — d3d12_manager.cpp
- `scripts/` — strip_exports.py, fix_cpp_classnames.py
- Build files — multiple .vcxproj retargeted to v142

## 11. Existing Constraints

- **Code formatting**: `.clang-format` — Chromium-based, 100-char limit, 2-space indent
- **Build**: Visual Studio 2019 (v142 toolset), MSBuild
- **License**: MIT (inherited from upstream)

## 12. Existing Automation

| Script | Purpose |
|--------|---------|
| `scripts/strip_renderdoc_signatures.py` | Post-build string obfuscation |
| `scripts/fix_cpp_classnames.py` | Class name fixup post-build |
| `util/clang_format_all.sh` | Bulk code formatting |
| `util/buildscripts/` | CI/CD build automation |
| `docs/verify-docstrings.py` | Docstring verification |
| `docs/regenerate_stubs.py` | Python stub generation |
| `.github/workflows/ci.yml` | Full CI pipeline |

## Anti-Detection Modifications (unique to this fork)

Listed in the latest commit:
1. `strip_exports.py` — post-build stripping of RENDERDOC strings from binaries
2. VK layer name remap → `VK_LAYER_MICROSOFT_SystemLoad`
3. All `renderdoc`/`RenderDoc`/`RENDERDOC` strings → `sqcaptlib`/`SqCapLib_`/`SQCAPTLIB`
4. Stealth headers: `string_obfuscation.h`, `stealth_remap.h`, `env_cleanup.h`, `vk_layer_hide.h`
5. Version DLL proxy + global hook launcher for stealth injection
6. Diagnostic logging in CreateProcessW failure path (`win32_process.cpp`)
7. UI string rebranding across qrenderdoc
8. Build retargeted to v142 (VS2019) toolset

## Recent Bug Fixes (2026-05-21)

**DllMain CacheSelfModuleHandle race condition**: Fixed "Can't find required export function in system_load.dll" error in tool processes. Root cause: `win32_libentry.cpp` DllMain excluded tool processes from `CacheSelfModuleHandle()`, but `LaunchAndInjectIntoProcess` depends on `g_CachedSelfHandle`/`g_CachedProcAddrs` being populated. Fix: call `CacheSelfModuleHandle()` for ALL process types before the exclusion check; only skip `add_hooks()` for tool processes. Also added `GetCachedProcAddress` → `GetProcAddress` fallback in `LaunchAndInjectIntoProcess` for robustness.

## Harness Profile

- **Project Type**: software
- **Agents**: build-error-resolver, code-reviewer, security-reviewer
- **Skills**: API design, core architecture, database (N/A), testing
- **Rules**: `.claude/rules/software/api.md`, `core.md`, `db.md`, `tests.md`
