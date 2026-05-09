/******************************************************************************
 * Stealth Remapping - Memory Anti-Detection
 *
 * This file remaps all RENDERDOC_* symbols to neutral names to avoid
 * memory scanning detection by anti-cheat systems.
 *
 * Include this file FIRST in any compilation unit that exports symbols.
 ******************************************************************************/

#pragma once

// ============================================================================
// Core Symbol Remapping
// ============================================================================

// Prevent symbol name leakage in memory
#ifdef RENDERDOC_EXPORTS

// GUID obfuscation
#define RENDERDOC_DeleteSelf         SL_DeleteSelf_GUID
#define RENDERDOC_ShaderDebugMagicValue SL_ShaderDebugMagic_GUID

// NOTE: We do NOT remap RENDERDOC_* function names here because many of them
// are both exported AND called internally across .lib boundaries. The #define
// approach breaks when the definition and call site are in different compilation
// units with different include orders.
//
// Instead, we rely on:
// 1. The DEF file (system_load.def) to create SL_* export aliases
// 2. PE header erasure + PEB unlink to prevent anti-cheat from reading the export table
// 3. The DLL being loaded via d3d11 proxy sideloading (not as a named module)

// GetAPI is the single most scanned export by anti-cheat — remap it
// (defined in entry_points.cpp only, not called internally)
#define RENDERDOC_GetAPI                SL_GetAPI

#endif // RENDERDOC_EXPORTS

// ============================================================================
// Function Remapping - ALWAYS AVAILABLE FOR INTERNAL USE
// ============================================================================
// These function remappings must be available in ALL internal compilation units,
// not just when RENDERDOC_EXPORTS is defined.

#ifndef RENDERDOC_NumVerticesPerPrimitive
#endif

#ifndef RENDERDOC_VertexOffset
#endif

#ifndef RENDERDOC_CreateTargetControl
#endif

#ifndef RENDERDOC_OpenCaptureFile
#endif

#ifndef RENDERDOC_SaveConfigSettings
#endif

#ifndef RENDERDOC_SetDebugLogFile
#endif

// ============================================================================
// Macro Definitions - ALWAYS AVAILABLE
// ============================================================================
// These macros must be available in ALL compilation units, not just when
// RENDERDOC_EXPORTS is defined, because they're used throughout the codebase.

#ifndef SLASSERT
#define SLASSERT(condition, ...) do { if(!(condition)) { OS_DEBUG_BREAK(); } } while(0)
#endif

#ifndef SLLOG
#define SLLOG(...) rdclog(LogType::Comment, __VA_ARGS__)
#endif

#ifndef SLDEBUG
#define SLDEBUG(...) rdclog(LogType::Debug, __VA_ARGS__)
#endif

#ifndef SLERR
#define SLERR(...) rdclog(LogType::Error, __VA_ARGS__)
#endif

#ifndef SLWARN
#define SLWARN(...) rdclog(LogType::Warning, __VA_ARGS__)
#endif

#ifndef SLFATAL
#define SLFATAL(...) \
  do { \
    rdclog(LogType::Fatal, __VA_ARGS__); \
    rdclog_flush(); \
    OS_DEBUG_BREAK(); \
  } while(0)
#endif

#ifndef SLCOMPILE_ASSERT
#define SLCOMPILE_ASSERT(expr, msg) static_assert(expr, msg)
#endif// ============================================================================
// String Obfuscation Macros
// ============================================================================

// Use these macros for any string literals containing sensitive names
#define OBFUSCATE_STR(x) x
#define SL_NAME "SystemLoad"
#define SL_DESCRIPTION "System Resource Manager"

// ============================================================================
// Vulkan Layer Remapping
// ============================================================================

#define VK_LAYER_RENDERDOC_Capture              VK_LAYER_MICROSOFT_SystemLoad
#define VK_LAYER_SystemLoad_Capture             VK_LAYER_MICROSOFT_SystemLoad
#define RENDERDOC_CaptureGetInstanceProcAddr    SL_GetInstanceProcAddr
#define RENDERDOC_CaptureGetDeviceProcAddr      SL_GetDeviceProcAddr

// ============================================================================
// Internal namespace obfuscation
// ============================================================================

// Only define namespace if not already defined
#ifndef SYSTEMLOAD_NAMESPACE_DEFINED
#define SYSTEMLOAD_NAMESPACE_DEFINED
// Use a different name to avoid conflicts with Windows headers
namespace SystemLoadNS {
  // All internal code should use SystemLoad namespace instead of RenderDoc
}

// Don't create namespace alias to avoid conflicts with SanQiInternalLib class
// namespace RenderDoc = SystemLoad;
#endif


