# CLAUDE.md — SanQi Capture (RenderDoc Fork)

# harness-profile: software

## Project Identity

This is a **fork of RenderDoc** rebranded as **SanQi Capture (SqCap)** — a graphics frame-capture debugger for
D3D11/D3D12/Vulkan/OpenGL. The fork adds anti-detection/stealth features for Windows x64 game environments.

**Branch**: `KID_V1.X` (tracks upstream `v1.x`)
**Author**: zhongduanmin
**License**: MIT (inherited)

## Architecture Overview

**Data flow**: Target app → [shim injection] → renderdoc.dll → API hooks → driver wrappers → serialization → .rdc
**Replay flow**: .rdc file → deserialize → replay engine → shader debug / texture view / mesh view
**Key binaries**: `system_load.dll` (core, was renderdoc.dll) | `qsanqiInjectTool.exe` (Qt5 GUI, was qrenderdoc.exe) | `sanqicapture.exe` (CLI, was renderdoccmd.exe) | `system_shim64.dll` (stealth injector) | `d3d11_proxy.dll` (injection proxy, stripped exports)

Full topology diagram in `ARCHITECTURE.md`.

## Module Index

| Directory | Purpose | Key Files |
|-----------|---------|-----------|
| `renderdoc/driver/vulkan/` | Vulkan capture + replay | `vk_core.cpp`, `vk_serialise.cpp`, `vk_shaderdebug.cpp` |
| `renderdoc/driver/d3d12/` | D3D12 capture + replay | `d3d12_command_list_wrap.cpp`, `d3d12_manager.cpp` |
| `renderdoc/driver/d3d11/` | D3D11 capture | `d3d11_context_wrap.cpp` |
| `renderdoc/driver/gl/` | OpenGL/GLES capture | `gl_driver.cpp`, `wrappers/gl_texture_funcs.cpp` |
| `renderdoc/driver/dxgi/` | DXGI swapchain capture | |
| `renderdoc/driver/shaders/dxil/` | DXIL shader debugging | `dxil_debug.cpp`, `dxil_disassemble.cpp` |
| `renderdoc/driver/shaders/spirv/` | SPIR-V shader processing | `spirv_gen.cpp` |
| `renderdoc/driver/ihv/` | GPU vendor extensions (AMD/NV/Intel/ARM) | |
| `renderdoc/api/` | Public C API | `app/renderdoc_app.h`, `replay/renderdoc_replay.h` |
| `renderdoc/core/` | Core engine, settings, stealth | `stealth_remap.h`, `remote_server.cpp`, `settings.cpp` |
| `renderdoc/os/win32/` | Windows platform layer + stealth injections | `win32_process.cpp`, `win32_stealth.h`, `win32_libentry.cpp` |
| `renderdoc/replay/` | Replay engine (frame playback) | `common/` |
| `renderdoc/serialise/` | Capture file serialization | `codecs/` |
| `renderdoc/hooks/` | API hook definitions | |
| `renderdoc/3rdparty/` | Vendored deps (breakpad, glslang, pugixml, etc.) | |
| `qrenderdoc/Code/` | Qt GUI core | `qrenderdoc.cpp`, `Interface/QRDInterface.h` |
| `qrenderdoc/Widgets/` | Custom Qt widgets | |
| `qrenderdoc/Windows/` | Window classes (dialogs, pipeline state) | |
| `renderdoccmd/` | CLI tool | `renderdoccmd.cpp` (52KB), `renderdoccmd_win32.cpp` |
| `renderdocshim/` | Injection shim DLL | `renderdocshim.cpp` |
| `scripts/` | Build helper scripts | `strip_renderdoc_signatures.py`, `fix_cpp_classnames.py` |
| `util/` | Build/installer/test infrastructure | `buildscripts/`, `test/demos/` |
| `docs/` | Sphinx user docs + Harness Engineering docs | |

## Operational Landmines

1. **Anti-detection string convention**: All `renderdoc`/`RenderDoc`/`RENDERDOC` → `sqcaptlib`/`SqCapLib_`/`SQCAPTLIB`. New strings MUST follow this pattern. Post-build `strip_renderdoc_signatures.py` strips remaining occurrences — use `string_obfuscation.h` for any compile-time strings.

2. **VK layer name**: Uses `VK_LAYER_MICROSOFT_SystemLoad` (not `VK_LAYER_RENDERDOC_Capture`). Do not change.

3. **v142 toolset only**: All .vcxproj files use v142 (VS2019). Don't upgrade to v143 without testing stealth injection.

4. **Stealth headers are hard dependencies**: `win32_stealth.h`, `win32_ntquery_hook.h`, `win32_vk_layer_hide.h`, `stealth_remap.h` — do not remove or refactor without understanding the full injection pipeline.

5. **Repo-root build artifacts**: `build_*.txt`, `build_*.bat`, `x64/` are debug artifacts from anti-detection work. Do not commit more of these.

6. **DllMain CacheSelfModuleHandle**: `CacheSelfModuleHandle()` MUST be called for ALL process types (tool + target) in DllMain before any early-return path. Tool processes (qrenderdoc/qsanqiinjecttool) skip `add_hooks()` but still need the cache — `LaunchAndInjectIntoProcess` and `InjectIntoProcess` depend on `GetCachedSelfModuleHandle()` and `GetCachedProcAddress()` being populated. Breaking this causes "Can't find required export function" error.

## Build Quick Reference

```bash
# VS2022 (v143 toolset), Development|x64
# cmd //c "E:\work\sqcap_src\build_me.bat"  (full solution rebuild)
# Or open renderdoc.sln in VS2022, select Development|x64 or Release|x64
# Post-build: strip_exports.py + patch_tls.py run automatically
```

See `docs/CONTRIBUTING/Compiling.md` for detailed instructions.

## Global Constraints

- See `~/.claude/CLAUDE.md` for Harness Engineering SOP (global enforcement)
- See `~/.claude/harness/SOP.md` for full SOP specification
- Never commit without explicit user request (see global CLAUDE.md)
- Code style: `.clang-format` at repo root (Chromium-based, 100 cols)

## Doc Pointers

| Resource | Path |
|----------|------|
| Architecture details | `ARCHITECTURE.md` |
| Current state snapshot | `docs/evidence/current-state.md` |
| Design docs index | `docs/design-docs/index.md` |
| Execution plans | `docs/exec-plans/active/` |
| Tech debt tracker | `docs/exec-plans/tech-debt-tracker.md` |
| Product specs | `docs/product-specs/index.md` |
| External references | `docs/references/` |
| Upstream README | `README.md` |
| Contributing | `docs/CONTRIBUTING.md` |

## Harness Profile

- **类型**: software
- **可用 Agents (3)**: build-error-resolver, code-reviewer, security-reviewer
- **可用 Skills (4)**: 通用编码规范、Git 工作流、安全规范、测试规范
- **路径规则**: `.claude/rules/software/api.md`, `core.md`, `db.md`, `tests.md`
- **全局约束**: `~/.claude/CLAUDE.md` (Harness Engineering SOP), `~/.claude/rules/harness/` (通用规则), `~/.claude/rules/harness/languages/cpp.md`
