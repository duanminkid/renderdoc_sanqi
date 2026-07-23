# ARCHITECTURE.md — SanQi Capture (RenderDoc Fork)

## High-Level Topology

```
┌──────────────────────────────────────────────────────────────┐
│                     TARGET APPLICATION                       │
│  (D3D11 / D3D12 / Vulkan / OpenGL / GLES game or app)       │
└─────────────────────┬────────────────────────────────────────┘
                      │ API calls (D3D/VK/GL)
                      ▼
┌──────────────────────────────────────────────────────────────┐
│                  RENDERDOCSHIM.DLL                           │
│  Stealth injection launcher                                  │
│  • Version DLL proxy (winmm.dll / version.dll)              │
│  • Global hook (SetWindowsHookEx)                           │
│  • Loads renderdoc.dll into target process                   │
└─────────────────────┬────────────────────────────────────────┘
                      │ LoadLibrary("renderdoc.dll")
                      ▼
┌──────────────────────────────────────────────────────────────┐
│                    RENDERDOC.DLL                             │
│  Core capture + replay engine                               │
│                                                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                HOOKS (vtable/import hooking)           │  │
│  │  renderdoc/hooks/ — minhook, plthook                   │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                    │
│  ┌───────────────────────┼───────────────────────────────┐  │
│  │                  DRIVERS                               │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐   │  │
│  │  │  D3D12   │ │  Vulkan  │ │  D3D11   │ │   GL   │   │  │
│  │  │  driver  │ │  driver  │ │  driver  │ │ driver │   │  │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘   │  │
│  │       │            │            │           │         │  │
│  │  ┌────┴────────────┴────────────┴───────────┴─────┐   │  │
│  │  │           SHADER PROCESSING                     │   │  │
│  │  │  DXBC  │  DXIL  │  SPIR-V (via glslang)        │   │  │
│  │  └────────────────────────────────────────────────┘   │  │
│  │       │            │            │           │         │  │
│  │  ┌────┴────────────┴────────────┴───────────┴─────┐   │  │
│  │  │         SERIALIZATION ENGINE                    │   │  │
│  │  │  Stream-based binary format → .rdc files       │   │  │
│  │  └────────────────────────────────────────────────┘   │  │
│  │                                                        │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │              REPLAY ENGINE                       │  │  │
│  │  │  Frame playback, shader debugging, mesh viewing │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │                                                        │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │         STEALTH / ANTI-DETECTION LAYER           │  │  │
│  │  │  String obfuscation, VK layer hiding,            │  │  │
│  │  │  NtQuerySystemInformation hooks, env cleanup     │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
           │                              │
           ▼                              ▼
┌──────────────────────┐    ┌──────────────────────┐
│   RENDERDOCCMD.EXE   │    │    QRENDERDOC.EXE     │
│   CLI tool           │    │    Qt5 GUI            │
│   • Capture control  │    │    • Frame inspection │
│   • Replay to disk   │    │    • Shader debugger  │
│   • Batch operations │    │    • Mesh viewer      │
│                      │    │    • Python scripting │
│                      │    │    • Extensions API   │
└──────────────────────┘    └──────────────────────┘
```

## Module Boundaries

### renderdoc.dll → Target Application
- **Direction**: renderdoc hooks INTO the target app
- **Mechanism**: VTable and import-address-table hooks via minhook/plthook
- **Interface**: Graphics API calls (D3D11/12, Vulkan, GL) intercepted at entry/exit

### renderdoc.dll → renderdoccmd.exe
- **Direction**: renderdoccmd calls INTO renderdoc via public API
- **Interface**: `renderdoc/api/app/renderdoc_app.h` (RENDERDOC_API_1_6_0)
- **IPC**: Network socket for remote capture control (`renderdoc/core/remote_server.cpp`)

### renderdoc.dll → qrenderdoc.exe
- **Direction**: qrenderdoc calls INTO renderdoc via replay API
- **Interface**: `renderdoc/api/replay/renderdoc_replay.h`
- **Extension points**: `qrenderdoc/Code/Interface/QRDInterface.h`

### renderdocshim.dll → renderdoc.dll
- **Direction**: renderdocshim loads renderdoc.dll into target process
- **Mechanism**: DLL injection via version.dll proxy or Windows hook
- **Config**: Stealth-launch configuration from registry or environment

## Dependency Direction

```
                    ┌─────────────┐
                    │   common/   │  ← No dependencies
                    └──────┬──────┘
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌──────────┐   ┌──────────────┐  ┌───────────┐
    │ serialise/│  │   maths/     │  │  strings/ │
    └─────┬─────┘  └──────────────┘  └───────────┘
          │
    ┌─────┼─────────────────────────┐
    ▼     ▼                         ▼
┌──────┐ ┌──────┐             ┌──────────────┐
│ core │ │  os  │             │     api/     │
└──┬───┘ └──┬───┘             └──────────────┘
   │        │
   └───────┬┼──────────────────────┐
           ▼▼                      ▼
    ┌─────────────┐        ┌──────────────┐
    │   driver/   │───────▶│   replay/    │
    │ (per-API)   │        │              │
    └─────────────┘        └──────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
            ┌────────────┐ ┌────────────┐ ┌────────────┐
            │renderdoccmd│ │ qrenderdoc │ │renderdocshim│
            └────────────┘ └────────────┘ └────────────┘
```

**Rules**:
- `common/`, `maths/`, `strings/` have no internal dependencies (leaf modules)
- `driver/` → depends on `core/`, `os/`, `serialise/`
- `replay/` → depends on `driver/` (shader processing), `serialise/`
- `renderdoccmd` → depends on all of renderdoc
- `qrenderdoc` → depends on replay API + renderdoccmd IPC
- No circular dependencies allowed

## Stealth Architecture (Fork-Specific)

```
┌─────────────────────────────────────────────────┐
│              STEALTH INJECTION CHAIN             │
│                                                  │
│  1. Version DLL Proxy                            │
│     winmm.dll / version.dll placed next to .exe  │
│     → OS loads our DLL instead of system DLL     │
│                                                  │
│  2. Global Hook Launcher                         │
│     SetWindowsHookEx injects into new processes  │
│                                                  │
│  3. Brand Obfuscation                            │
│     All "RenderDoc" strings → "SqCapLib"         │
│     VK_LAYER name → VK_LAYER_MICROSOFT_SystemLoad│
│     Post-build binary string stripping           │
│                                                  │
│  4. Runtime Anti-Detection                       │
│     NtQuerySystemInformation hook (hide DLL)     │
│     Environment variable cleanup                 │
│     VK layer enumeration hiding                   │
└─────────────────────────────────────────────────┘
```

Key files:
- `renderdoc/os/win32/win32_stealth.h` — process-level stealth operations
- `renderdoc/os/win32/win32_ntquery_hook.h` — NtQuerySystemInformation hook
- `renderdoc/os/win32/win32_vk_layer_hide.h` — Vulkan layer enumeration hiding
- `renderdoc/core/stealth_remap.h` — string/name remapping table
- `renderdoc/core/string_obfuscation.h` — compile-time string obfuscation
- `scripts/strip_renderdoc_signatures.py` — post-build binary string stripping
- `renderdoc/os/win32/version_proxy.vcxproj` — version.dll proxy project

## Build Configuration

| Configuration | Purpose |
|--------------|---------|
| `Development|x64` | Debug build with asserts and diagnostics |
| `Release|x64` | Stripped, optimized production build |
| `Development|x86` | 32-bit debug (rarely used) |
| `Release|x86` | 32-bit release (rarely used) |

Main development targets: **Development|x64** for debugging, **Release|x64** for production.
