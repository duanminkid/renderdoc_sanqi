/******************************************************************************
 * d3d11.dll Proxy — Single DLL, 3DMigoto-style Architecture
 *
 * Architecture matches 3DMigoto exactly:
 *   - DllMain: only save handle + DisableThreadLibraryCalls (NO threads)
 *   - Lazy init: first D3D11CreateDevice call triggers synchronous init
 *   - Init loads real d3d11.dll from System32, then installs hooks
 *   - All other exports are stubs forwarding to real d3d11.dll
 *   - No background threads, no events, no stealth operations
 *
 * IMPORTANT: The proxy intercepts D3D11CreateDevice/AndSwapChain and routes
 * them through the hook engine's wrapping logic (CreateD3D11_Internal).
 * The hook engine does NOT register IAT hooks for d3d11.dll in proxy mode,
 * because the proxy already handles interception. This avoids the recursive
 * conflict where the hook system would treat our proxy as the real d3d11.dll.
 *
 * This avoids:
 *   - PsSetCreateThreadNotifyRoutine detection (no CreateThread)
 *   - PsSetLoadImageNotifyRoutine detection (no LoadLibrary of custom DLLs)
 *   - Heuristic detection of PE erasure / PEB unlink
 ******************************************************************************/

#include <windows.h>
#include "win32_hook_log.h"

// MinHook — inline hooking for injection mode
#include <MinHook.h>

// ============================================================================
// Raw Win32 log — works even inside DllMain (loader lock), no CRT dependency
// Writes to "d3d11_proxy_trace.log" in the same directory as the DLL
// ============================================================================
static void RawTrace(const char *msg)
{
  // Build log path next to our DLL (game directory)
  static char s_logPath[MAX_PATH] = {0};
  if(s_logPath[0] == '\0')
  {
    // Get our DLL's own path
    HMODULE hSelf = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&RawTrace, &hSelf);
    if(hSelf)
    {
      GetModuleFileNameA(hSelf, s_logPath, MAX_PATH);
      // Strip filename, keep directory
      char *lastSlash = s_logPath;
      for(char *p = s_logPath; *p; p++)
        if(*p == '\\' || *p == '/') lastSlash = p;
      *(lastSlash + 1) = '\0';
    }
    else
    {
      // Fallback: current directory
      s_logPath[0] = '.';
      s_logPath[1] = '\\';
      s_logPath[2] = '\0';
    }
    lstrcatA(s_logPath, "d3d11_proxy_trace.log");
  }

  HANDLE hFile = CreateFileA(s_logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(hFile != INVALID_HANDLE_VALUE)
  {
    DWORD written;
    WriteFile(hFile, msg, (DWORD)lstrlenA(msg), &written, NULL);
    CloseHandle(hFile);
  }

  OutputDebugStringA(msg);
}

// ============================================================================
// State
// ============================================================================

static HMODULE g_hRealD3D11 = NULL;
static volatile LONG g_initOnce = 0;    // 0=not started, 1=in progress, 2=done

// Our own module handle, saved in DllMain before any stealth/PEB-unlink.
// After PEB unlink, GetModuleHandleA("system_load.dll") returns NULL,
// and in proxy mode the filename is "d3d11.dll" so it never matched anyway.
// This cached handle is the ONLY reliable way to reference ourselves.
HMODULE g_hSelf = NULL;

// Global flag: we are running as a d3d11.dll proxy (sideloaded into game dir).
// The hook engine checks this to skip IAT-hooking d3d11.dll (we handle it).
// Defined here, declared extern in d3d11_hooks.cpp.
bool g_D3D11ProxyMode = false;

// Accessor for other translation units (avoids extern HMODULE across the codebase).
extern "C" HMODULE GetSelfModuleHandle()
{
  return g_hSelf;
}

// ============================================================================
// Real d3d11.dll function pointers
// ============================================================================

typedef HRESULT(WINAPI *pfnD3D11CreateDevice)(void *, int, HMODULE, UINT, const void *, UINT, UINT,
                                               void **, void *, void **);
typedef HRESULT(WINAPI *pfnD3D11CreateDeviceAndSwapChain)(void *, int, HMODULE, UINT, const void *,
                                                           UINT, UINT, const void *, void **,
                                                           void **, void *, void **);
typedef HRESULT(WINAPI *pfnGeneric)();
typedef int(WINAPI *pfnIntGeneric)();

static pfnD3D11CreateDevice real_D3D11CreateDevice = NULL;
static pfnD3D11CreateDeviceAndSwapChain real_D3D11CreateDeviceAndSwapChain = NULL;
static pfnGeneric real_D3D11CoreCreateDevice = NULL;
static pfnGeneric real_D3D11CoreCreateLayeredDevice = NULL;
static pfnGeneric real_D3D11CoreGetLayeredDeviceSize = NULL;
static pfnGeneric real_D3D11CoreRegisterLayers = NULL;
static pfnGeneric real_D3D11CreateDeviceForD3D12 = NULL;
static pfnGeneric real_EnableFeatureLevelUpgrade = NULL;
static pfnGeneric real_D3D11On12CreateDevice = NULL;
static pfnGeneric real_CreateDirect3D11DeviceFromDXGIDevice = NULL;
static pfnGeneric real_CreateDirect3D11SurfaceFromDXGISurface = NULL;
static pfnIntGeneric real_D3DKMTQueryAdapterInfo = NULL;
static pfnGeneric real_D3DKMTOpenAdapterFromHdc = NULL;
static pfnGeneric real_D3DKMTOpenResource = NULL;
static pfnGeneric real_D3DKMTQueryResourceInfo = NULL;
static pfnGeneric real_D3DKMTEscape = NULL;
static pfnGeneric real_D3DKMTGetDeviceState = NULL;

// Forward declarations from win32_libentry.cpp
extern "C" BOOL add_hooks();
extern "C" void ApplyStealthMeasures(HMODULE hModule);

// Bridge function implemented in d3d11_hooks.cpp — routes device creation
// through the SanQi Capture wrapping logic (WrappedID3D11Device etc.)
// This is the ONLY path for D3D11 device creation in proxy mode.
extern "C" HRESULT ProxyBridge_D3D11CreateDeviceAndSwapChain(
    void *realCreateDevice, void *realCreateDeviceAndSwapChain,
    void *pAdapter, int DriverType, HMODULE Software, UINT Flags,
    const void *pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    const void *pSwapChainDesc, void **ppSwapChain,
    void **ppDevice, void *pFeatureLevel, void **ppImmediateContext);

// ============================================================================
// Lazy initialization — called on first D3D API call (like 3DMigoto)
// ============================================================================

static void LazyInit()
{
  // Atomic test-and-set: only the first thread proceeds (0 -> 1).
  // Other threads spin-wait until initialization is complete (2).
  LONG prev = InterlockedCompareExchange(&g_initOnce, 1, 0);
  if(prev == 2)
    return;    // already fully initialized
  if(prev == 1)
  {
    // Another thread is currently initializing — spin until done.
    while(InterlockedCompareExchange(&g_initOnce, 2, 2) != 2)
      Sleep(1);
    return;
  }
  // prev == 0: we are the initializer.

  // Mark proxy mode so any code that checks knows we are a d3d11.dll proxy.
  g_D3D11ProxyMode = true;

  // Load real d3d11.dll from System32
  wchar_t sysDir[MAX_PATH];
  GetSystemDirectoryW(sysDir, MAX_PATH);
  wcscat_s(sysDir, MAX_PATH, L"\\d3d11.dll");

  g_hRealD3D11 = LoadLibraryW(sysDir);

  if(g_hRealD3D11)
  {
    // Resolve all exports
    real_D3D11CreateDevice = (pfnD3D11CreateDevice)GetProcAddress(g_hRealD3D11, "D3D11CreateDevice");
    real_D3D11CreateDeviceAndSwapChain = (pfnD3D11CreateDeviceAndSwapChain)GetProcAddress(g_hRealD3D11, "D3D11CreateDeviceAndSwapChain");
    real_D3D11CoreCreateDevice = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3D11CoreCreateDevice");
    real_D3D11CoreCreateLayeredDevice = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3D11CoreCreateLayeredDevice");
    real_D3D11CoreGetLayeredDeviceSize = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3D11CoreGetLayeredDeviceSize");
    real_D3D11CoreRegisterLayers = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3D11CoreRegisterLayers");
    real_D3D11CreateDeviceForD3D12 = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3D11CreateDeviceForD3D12");
    real_EnableFeatureLevelUpgrade = (pfnGeneric)GetProcAddress(g_hRealD3D11, "EnableFeatureLevelUpgrade");
    real_D3D11On12CreateDevice = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3D11On12CreateDevice");
    real_CreateDirect3D11DeviceFromDXGIDevice = (pfnGeneric)GetProcAddress(g_hRealD3D11, "CreateDirect3D11DeviceFromDXGIDevice");
    real_CreateDirect3D11SurfaceFromDXGISurface = (pfnGeneric)GetProcAddress(g_hRealD3D11, "CreateDirect3D11SurfaceFromDXGISurface");
    real_D3DKMTQueryAdapterInfo = (pfnIntGeneric)GetProcAddress(g_hRealD3D11, "D3DKMTQueryAdapterInfo");
    real_D3DKMTOpenAdapterFromHdc = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3DKMTOpenAdapterFromHdc");
    real_D3DKMTOpenResource = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3DKMTOpenResource");
    real_D3DKMTQueryResourceInfo = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3DKMTQueryResourceInfo");
    real_D3DKMTEscape = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3DKMTEscape");
    real_D3DKMTGetDeviceState = (pfnGeneric)GetProcAddress(g_hRealD3D11, "D3DKMTGetDeviceState");

    HOOK_LOG("e=%p s=%p\n", real_D3D11CreateDevice, real_D3D11CreateDeviceAndSwapChain);
  }
  else
  {
    DWORD err = GetLastError();
    HOOK_LOG("load err=%u\n", err);
  }

  // Initialize core (proxy-safe: skips IAT/stealth/network when g_D3D11ProxyMode==true)
  add_hooks();

  // Apply stealth measures NOW — we're outside loader lock so this is safe.
  // In proxy mode the DLL sits in the game dir as d3d11.dll, making it
  // trivially detectable via PEB enumeration and NtQueryVirtualMemory.
  // PEB unlink + PE header wipe + NtQuery hook hide us from these scans.
  ApplyStealthMeasures(g_hSelf);

  // Mark fully initialized — wake any spinning threads.
  InterlockedExchange(&g_initOnce, 2);
}

// ============================================================================
// D3D11 Core exports — proxied with hooks
// ============================================================================

extern "C" {

HRESULT WINAPI Proxy_D3D11CreateDevice(
    void *pAdapter, int DriverType, HMODULE Software, UINT Flags, const void *pFeatureLevels,
    UINT FeatureLevels, UINT SDKVersion, void **ppDevice, void *pFeatureLevel,
    void **ppImmediateContext)
{
  RawTrace(">>> Proxy_D3D11CreateDevice called\n");
  HOOK_LOG("\n>>> Proxy_D3D11CreateDevice called\n");
  HOOK_LOG("  pAdapter=%p, DriverType=%d, Flags=%u, FeatureLevels=%u\n",
           pAdapter, DriverType, Flags, FeatureLevels);
  HOOK_LOG("  ppDevice=%p, ppImmediateContext=%p\n", ppDevice, ppImmediateContext);

  LazyInit();

  HOOK_LOG("  LazyInit done, real_CreateDevice=%p, real_CreateDeviceAndSwapChain=%p\n",
           real_D3D11CreateDevice, real_D3D11CreateDeviceAndSwapChain);
  HOOK_LOG("  Calling ProxyBridge...\n");

  // Route through the hook engine's wrapping logic.
  // This creates a WrappedID3D11Device instead of returning the raw device.
  // Pass NULL for swapchain parameters (D3D11CreateDevice doesn't have them).
  HRESULT hr = ProxyBridge_D3D11CreateDeviceAndSwapChain(
      (void *)real_D3D11CreateDevice, (void *)real_D3D11CreateDeviceAndSwapChain,
      pAdapter, DriverType, Software, Flags, pFeatureLevels,
      FeatureLevels, SDKVersion,
      NULL, NULL,    // no swap chain
      ppDevice, pFeatureLevel, ppImmediateContext);

  HOOK_LOG("<<< Proxy_D3D11CreateDevice returned HRESULT=0x%08X\n", (unsigned int)hr);
  return hr;
}

/* exported via .def */ HRESULT WINAPI Proxy_D3D11CreateDeviceAndSwapChain(
    void *pAdapter, int DriverType, HMODULE Software, UINT Flags, const void *pFeatureLevels,
    UINT FeatureLevels, UINT SDKVersion, const void *pSwapChainDesc, void **ppSwapChain,
    void **ppDevice, void *pFeatureLevel, void **ppImmediateContext)
{
  HOOK_LOG("\n>>> Proxy_D3D11CreateDeviceAndSwapChain called\n");
  HOOK_LOG("  pAdapter=%p, DriverType=%d, Flags=%u, FeatureLevels=%u\n",
           pAdapter, DriverType, Flags, FeatureLevels);
  HOOK_LOG("  pSwapChainDesc=%p, ppSwapChain=%p, ppDevice=%p\n",
           pSwapChainDesc, ppSwapChain, ppDevice);

  LazyInit();

  HOOK_LOG("  LazyInit done, calling ProxyBridge...\n");

  HRESULT hr = ProxyBridge_D3D11CreateDeviceAndSwapChain(
      (void *)real_D3D11CreateDevice, (void *)real_D3D11CreateDeviceAndSwapChain,
      pAdapter, DriverType, Software, Flags, pFeatureLevels,
      FeatureLevels, SDKVersion,
      pSwapChainDesc, ppSwapChain,
      ppDevice, pFeatureLevel, ppImmediateContext);

  HOOK_LOG("<<< Proxy_D3D11CreateDeviceAndSwapChain returned HRESULT=0x%08X\n", (unsigned int)hr);
  return hr;
}

// ============================================================================
// Additional D3D11 exports — forwarded to real d3d11.dll
// ============================================================================

/* exported via .def */ HRESULT WINAPI Proxy_D3D11CoreCreateDevice(
    void *a, void *b, void *c, UINT d, const void *e, UINT f, UINT g, void **h, void *i)
{
  LazyInit();
  if(real_D3D11CoreCreateDevice)
    return ((HRESULT(WINAPI *)(void *, void *, void *, UINT, const void *, UINT, UINT, void **, void *))
                real_D3D11CoreCreateDevice)(a, b, c, d, e, f, g, h, i);
  return E_FAIL;
}

/* exported via .def */ HRESULT WINAPI Proxy_D3D11CoreCreateLayeredDevice(void *a, UINT b, void *c, void *d, void **e)
{
  LazyInit();
  if(real_D3D11CoreCreateLayeredDevice)
    return ((HRESULT(WINAPI *)(void *, UINT, void *, void *, void **))real_D3D11CoreCreateLayeredDevice)(a, b, c, d, e);
  return E_FAIL;
}

/* exported via .def */ SIZE_T WINAPI Proxy_D3D11CoreGetLayeredDeviceSize(void *a, UINT b)
{
  LazyInit();
  if(real_D3D11CoreGetLayeredDeviceSize)
    return ((SIZE_T(WINAPI *)(void *, UINT))real_D3D11CoreGetLayeredDeviceSize)(a, b);
  return 0;
}

/* exported via .def */ HRESULT WINAPI Proxy_D3D11CoreRegisterLayers(void *a, UINT b)
{
  LazyInit();
  if(real_D3D11CoreRegisterLayers)
    return ((HRESULT(WINAPI *)(void *, UINT))real_D3D11CoreRegisterLayers)(a, b);
  return E_FAIL;
}

/* exported via .def */ HRESULT WINAPI Proxy_D3D11CreateDeviceForD3D12(void *a, void *b, UINT c, const void *d, UINT e, void **f, void *g, void **h)
{
  LazyInit();
  if(real_D3D11CreateDeviceForD3D12)
    return ((HRESULT(WINAPI *)(void *, void *, UINT, const void *, UINT, void **, void *, void **))
                real_D3D11CreateDeviceForD3D12)(a, b, c, d, e, f, g, h);
  return E_FAIL;
}

/* exported via .def */ HRESULT WINAPI Proxy_EnableFeatureLevelUpgrade()
{
  LazyInit();
  if(real_EnableFeatureLevelUpgrade) return real_EnableFeatureLevelUpgrade();
  return E_FAIL;
}

/* exported via .def */ HRESULT WINAPI Proxy_D3D11On12CreateDevice(void *a, UINT b, const void *c, UINT d, void **e, UINT f, UINT g, void **h, void **i, void *j)
{
  LazyInit();
  if(real_D3D11On12CreateDevice)
    return ((HRESULT(WINAPI *)(void *, UINT, const void *, UINT, void **, UINT, UINT, void **, void **, void *))
                real_D3D11On12CreateDevice)(a, b, c, d, e, f, g, h, i, j);
  return E_FAIL;
}

/* exported via .def */ HRESULT WINAPI Proxy_CreateDirect3D11DeviceFromDXGIDevice(void *a, void **b)
{
  LazyInit();
  if(real_CreateDirect3D11DeviceFromDXGIDevice)
    return ((HRESULT(WINAPI *)(void *, void **))real_CreateDirect3D11DeviceFromDXGIDevice)(a, b);
  return E_FAIL;
}

/* exported via .def */ HRESULT WINAPI Proxy_CreateDirect3D11SurfaceFromDXGISurface(void *a, void **b)
{
  LazyInit();
  if(real_CreateDirect3D11SurfaceFromDXGISurface)
    return ((HRESULT(WINAPI *)(void *, void **))real_CreateDirect3D11SurfaceFromDXGISurface)(a, b);
  return E_FAIL;
}

// ============================================================================
// D3DKMT stubs — most return 0, some forward to real d3d11.dll
// Matches real d3d11.dll export table exactly (3DMigoto pattern)
// ============================================================================

/* exported via .def */ int WINAPI Proxy_D3DKMTCloseAdapter() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTCreateAllocation() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTCreateContext() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTCreateDevice() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTCreateSynchronizationObject() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTDestroyAllocation() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTDestroyContext() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTDestroyDevice() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTDestroySynchronizationObject() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTGetContextSchedulingPriority() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTGetDisplayModeList() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTGetMultisampleMethodList() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTGetRuntimeData() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTGetSharedPrimaryHandle() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTLock() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTPresent() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTQueryAllocationResidency() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTRender() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTSetAllocationPriority() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTSetContextSchedulingPriority() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTSetDisplayMode() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTSetDisplayPrivateDriverFormat() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTSetGammaRamp() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTSetVidPnSourceOwner() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTSignalSynchronizationObject() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTUnlock() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTWaitForSynchronizationObject() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DKMTWaitForVerticalBlankEvent() { return 0; }

// D3DKMT functions that forward to real d3d11.dll
/* exported via .def */ int WINAPI Proxy_D3DKMTQueryAdapterInfo(void *info)
{
  LazyInit();
  if(real_D3DKMTQueryAdapterInfo) return ((int(WINAPI *)(void *))real_D3DKMTQueryAdapterInfo)(info);
  return 0;
}
/* exported via .def */ HRESULT WINAPI Proxy_D3DKMTEscape(void *a) { LazyInit(); if(real_D3DKMTEscape) return ((HRESULT(WINAPI *)(void *))real_D3DKMTEscape)(a); return 0; }
/* exported via .def */ HRESULT WINAPI Proxy_D3DKMTGetDeviceState(void *a) { LazyInit(); if(real_D3DKMTGetDeviceState) return ((HRESULT(WINAPI *)(void *))real_D3DKMTGetDeviceState)(a); return 0; }
/* exported via .def */ HRESULT WINAPI Proxy_D3DKMTOpenAdapterFromHdc(void *a) { LazyInit(); if(real_D3DKMTOpenAdapterFromHdc) return ((HRESULT(WINAPI *)(void *))real_D3DKMTOpenAdapterFromHdc)(a); return 0; }
/* exported via .def */ HRESULT WINAPI Proxy_D3DKMTOpenResource(void *a) { LazyInit(); if(real_D3DKMTOpenResource) return ((HRESULT(WINAPI *)(void *))real_D3DKMTOpenResource)(a); return 0; }
/* exported via .def */ HRESULT WINAPI Proxy_D3DKMTQueryResourceInfo(void *a) { LazyInit(); if(real_D3DKMTQueryResourceInfo) return ((HRESULT(WINAPI *)(void *))real_D3DKMTQueryResourceInfo)(a); return 0; }
/* exported via .def */ int WINAPI Proxy_OpenAdapter10(void *a) { LazyInit(); pfnIntGeneric fn = (pfnIntGeneric)GetProcAddress(g_hRealD3D11, "OpenAdapter10"); if(fn) return fn(); return 0; }
/* exported via .def */ int WINAPI Proxy_OpenAdapter10_2(void *a) { LazyInit(); pfnIntGeneric fn = (pfnIntGeneric)GetProcAddress(g_hRealD3D11, "OpenAdapter10_2"); if(fn) return fn(); return 0; }

// D3DPerformance stubs
/* exported via .def */ int WINAPI Proxy_D3DPerformance_BeginEvent(UINT64 a, const wchar_t *b) { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DPerformance_EndEvent() { return 0; }
/* exported via .def */ UINT WINAPI Proxy_D3DPerformance_GetStatus() { return 0; }
/* exported via .def */ int WINAPI Proxy_D3DPerformance_SetMarker(UINT64 a, const wchar_t *b) { return 0; }

// ============================================================================
// CBTProc — SetWindowsHookEx callback for DLL injection
//
// Used by the injector (qsanqiInjectTool.exe) to load this DLL into the game
// process via SetWindowsHookEx(WH_CBT, CBTProc, hModule, 0).
// The callback itself does nothing — just passes the hook chain.
// All actual work happens in DllMain(DLL_PROCESS_ATTACH).
// Matches 3DMigoto's CBTProc pattern exactly.
// ============================================================================
/* exported via .def */ LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam)
{
  return CallNextHookEx(0, nCode, wParam, lParam);
}

}    // extern "C"

// ============================================================================
// Injection init thread — writes diagnostic marker.
// D3D11 inline hooks are already installed by D3D11Hook::RegisterHooks()
// (called via add_hooks → LibraryHooks::RegisterHooks in DllMain).
// This thread just confirms injection succeeded.
// ============================================================================
static DWORD WINAPI InjectionInitThread(LPVOID)
{
  char tmp[MAX_PATH];
  GetTempPathA(MAX_PATH, tmp);
  lstrcatA(tmp, "sl_inject_ok.txt");
  HANDLE hf = CreateFileA(tmp, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(hf != INVALID_HANDLE_VALUE)
  {
    char buf[256];
    wsprintfA(buf, "OK pid=%lu\r\n", GetCurrentProcessId());
    DWORD w;
    WriteFile(hf, buf, (DWORD)lstrlenA(buf), &w, NULL);
    CloseHandle(hf);
  }
  return 0;
}

// ============================================================================
// DllMain — Handles both proxy mode and injection mode
//
// Detection method (same as 3DMigoto):
//   if (hModule == GetModuleHandleA("d3d11.dll"))  → proxy mode (we ARE d3d11.dll)
//   else                                            → injection mode (loaded under different name)
//
// ANTI-CHEAT DESIGN (both modes):
//   DllMain does minimal work. No IAT hooks, no stealth, no network, no threads.
//   D3D11 interception through export forwarding (proxy) or Deviare hooks (injection).
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  if(ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    DisableThreadLibraryCalls(hModule);
    g_hSelf = hModule;

#ifdef RENDERDOC_EXPORTS
    // Detect mode: are we loaded as d3d11.dll (proxy) or under another name (injection)?
    // This matches 3DMigoto's detection: hinstDLL != GetModuleHandleA("d3d11.dll")
    bool isProxyMode = (hModule == GetModuleHandleA("d3d11.dll"));

    if(isProxyMode)
    {
      // Proxy mode: we ARE d3d11.dll in the game directory.
      // LazyInit will fire on first D3D11 API call.
      // No extra initialization here — anti-cheat safe.
    }
    else
    {
      // Injection mode (loaded via SetWindowsHookEx global hook).
      // Global hook injects into ALL processes — we must filter to only
      // initialize in the target game process.
      //
      // The UI tool writes the target exe name to %TEMP%\sl_target.txt
      // before installing the hook. We read it here to check if this
      // process is the intended target.
      char exeName[MAX_PATH] = {0};
      GetModuleFileNameA(NULL, exeName, MAX_PATH);
      const char *exeBase = exeName;
      for(const char *p = exeName; *p; p++)
        if(*p == '\\' || *p == '/') exeBase = p + 1;

      // Read target from shared temp file
      char targetExe[MAX_PATH] = {0};
      {
        char targetPath[MAX_PATH];
        GetTempPathA(MAX_PATH, targetPath);
        lstrcatA(targetPath, "sl_target.txt");
        HANDLE hf = CreateFileA(targetPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hf != INVALID_HANDLE_VALUE)
        {
          DWORD bytesRead = 0;
          ReadFile(hf, targetExe, MAX_PATH - 1, &bytesRead, NULL);
          CloseHandle(hf);
          // Strip trailing whitespace/newline
          for(int i = (int)bytesRead - 1; i >= 0 && (targetExe[i] == '\r' || targetExe[i] == '\n' || targetExe[i] == ' '); i--)
            targetExe[i] = '\0';
        }
      }

      bool isTarget = false;
      if(targetExe[0] != '\0')
        isTarget = (_stricmp(exeBase, targetExe) == 0);

      // Diagnostic: log ALL DllMain injection calls to diagnose filtering issues
      {
        char diagPath[MAX_PATH];
        GetTempPathA(MAX_PATH, diagPath);
        lstrcatA(diagPath, "sl_diag.txt");
        HANDLE hf = CreateFileA(diagPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hf != INVALID_HANDLE_VALUE)
        {
          char buf[512];
          wsprintfA(buf, "exe=%s target='%s' match=%d tempdir=", exeBase, targetExe, isTarget);
          // append the temp path itself so we can see if it differs
          char tmpDir[MAX_PATH];
          GetTempPathA(MAX_PATH, tmpDir);
          lstrcatA(buf, tmpDir);
          lstrcatA(buf, "\r\n");
          DWORD w;
          WriteFile(hf, buf, (DWORD)lstrlenA(buf), &w, NULL);
          CloseHandle(hf);
        }
      }

      if(isTarget)
      {
        // We're in the target game process (arrived via SetWindowsHookEx CBT injection).
        // Use full hook registration path — g_D3D11ProxyMode stays false so that
        // LibraryHooks::RegisterHooks() runs completely, activating D3D11/D3D12/Vulkan
        // interception via MinHook inline hooks on the real d3d11.dll.
        g_D3D11ProxyMode = false;
        add_hooks();
        SetLastError(0);

        // Spawn thread to install MinHook inline hooks on real d3d11.dll.
        // Cannot do LoadLibrary/MinHook inside DllMain (Loader Lock).
        // CreateThread from DllMain IS safe — thread starts after DllMain returns.
        HANDLE hThread = CreateThread(NULL, 0, InjectionInitThread, NULL, 0, NULL);
        if(hThread)
          CloseHandle(hThread);
      }
      // Non-target process: DLL stays loaded but inert (no hooks, no init).
      // It will be unloaded when UnhookWindowsHookEx is called by the UI tool.
    }
#else
    // Compiled as standalone d3d11_proxy.dll (version_proxy.vcxproj).
    // Always proxy mode.
#endif
  }
  else if(ul_reason_for_call == DLL_PROCESS_DETACH)
  {
    if(g_hRealD3D11)
    {
      FreeLibrary(g_hRealD3D11);
      g_hRealD3D11 = NULL;
    }
  }
  return TRUE;
}
