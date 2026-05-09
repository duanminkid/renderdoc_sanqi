/******************************************************************************
 * version.dll Proxy — Alternative DLL sideloading target
 *
 * Drop this DLL as "version.dll" in the game directory.
 * It forwards all version API calls to the real version.dll in System32
 * while initializing SanQiCapture capture hooks on first call.
 *
 * Advantages over d3d11.dll proxy:
 *   - version.dll is loaded by almost every Windows exe
 *   - Less scrutinized by anti-cheat than d3d11.dll
 *   - Works for both D3D11 and D3D12/Vulkan games
 ******************************************************************************/

#include <windows.h>

// ============================================================================
// State
// ============================================================================

static HMODULE g_hRealVersion = NULL;
static volatile LONG g_initOnce = 0;    // 0=not started, 1=in progress, 2=done

// Our own module handle
static HMODULE g_hSelf = NULL;

// Proxy mode flag — shared with the hook engine
extern bool g_D3D11ProxyMode;

// Forward declarations from win32_libentry.cpp
extern "C" BOOL add_hooks();
extern "C" void ApplyStealthMeasures(HMODULE hModule);

// ============================================================================
// Real version.dll function pointers
// ============================================================================

typedef BOOL(WINAPI *pfnGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL(WINAPI *pfnGetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD(WINAPI *pfnGetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef DWORD(WINAPI *pfnGetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef BOOL(WINAPI *pfnGetFileVersionInfoExA)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL(WINAPI *pfnGetFileVersionInfoExW)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD(WINAPI *pfnGetFileVersionInfoSizeExA)(DWORD, LPCSTR, LPDWORD);
typedef DWORD(WINAPI *pfnGetFileVersionInfoSizeExW)(DWORD, LPCWSTR, LPDWORD);
typedef DWORD(WINAPI *pfnVerFindFileA)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD(WINAPI *pfnVerFindFileW)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
typedef DWORD(WINAPI *pfnVerInstallFileA)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
typedef DWORD(WINAPI *pfnVerInstallFileW)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
typedef DWORD(WINAPI *pfnVerLanguageNameA)(DWORD, LPSTR, DWORD);
typedef DWORD(WINAPI *pfnVerLanguageNameW)(DWORD, LPWSTR, DWORD);
typedef BOOL(WINAPI *pfnVerQueryValueA)(LPCVOID, LPCSTR, LPVOID *, PUINT);
typedef BOOL(WINAPI *pfnVerQueryValueW)(LPCVOID, LPCWSTR, LPVOID *, PUINT);

static pfnGetFileVersionInfoA real_GetFileVersionInfoA;
static pfnGetFileVersionInfoW real_GetFileVersionInfoW;
static pfnGetFileVersionInfoSizeA real_GetFileVersionInfoSizeA;
static pfnGetFileVersionInfoSizeW real_GetFileVersionInfoSizeW;
static pfnGetFileVersionInfoExA real_GetFileVersionInfoExA;
static pfnGetFileVersionInfoExW real_GetFileVersionInfoExW;
static pfnGetFileVersionInfoSizeExA real_GetFileVersionInfoSizeExA;
static pfnGetFileVersionInfoSizeExW real_GetFileVersionInfoSizeExW;
static pfnVerFindFileA real_VerFindFileA;
static pfnVerFindFileW real_VerFindFileW;
static pfnVerInstallFileA real_VerInstallFileA;
static pfnVerInstallFileW real_VerInstallFileW;
static pfnVerLanguageNameA real_VerLanguageNameA;
static pfnVerLanguageNameW real_VerLanguageNameW;
static pfnVerQueryValueA real_VerQueryValueA;
static pfnVerQueryValueW real_VerQueryValueW;

// ============================================================================
// Lazy initialization
// ============================================================================

static void LazyInit()
{
  LONG prev = InterlockedCompareExchange(&g_initOnce, 1, 0);
  if(prev == 2) return;
  if(prev == 1) { while(InterlockedCompareExchange(&g_initOnce, 2, 2) != 2) Sleep(1); return; }

  g_D3D11ProxyMode = true;

  // Load real version.dll from System32
  wchar_t sysDir[MAX_PATH];
  GetSystemDirectoryW(sysDir, MAX_PATH);
  wcscat_s(sysDir, MAX_PATH, L"\\version.dll");
  g_hRealVersion = LoadLibraryW(sysDir);

  if(g_hRealVersion)
  {
    real_GetFileVersionInfoA = (pfnGetFileVersionInfoA)GetProcAddress(g_hRealVersion, "GetFileVersionInfoA");
    real_GetFileVersionInfoW = (pfnGetFileVersionInfoW)GetProcAddress(g_hRealVersion, "GetFileVersionInfoW");
    real_GetFileVersionInfoSizeA = (pfnGetFileVersionInfoSizeA)GetProcAddress(g_hRealVersion, "GetFileVersionInfoSizeA");
    real_GetFileVersionInfoSizeW = (pfnGetFileVersionInfoSizeW)GetProcAddress(g_hRealVersion, "GetFileVersionInfoSizeW");
    real_GetFileVersionInfoExA = (pfnGetFileVersionInfoExA)GetProcAddress(g_hRealVersion, "GetFileVersionInfoExA");
    real_GetFileVersionInfoExW = (pfnGetFileVersionInfoExW)GetProcAddress(g_hRealVersion, "GetFileVersionInfoExW");
    real_GetFileVersionInfoSizeExA = (pfnGetFileVersionInfoSizeExA)GetProcAddress(g_hRealVersion, "GetFileVersionInfoSizeExA");
    real_GetFileVersionInfoSizeExW = (pfnGetFileVersionInfoSizeExW)GetProcAddress(g_hRealVersion, "GetFileVersionInfoSizeExW");
    real_VerFindFileA = (pfnVerFindFileA)GetProcAddress(g_hRealVersion, "VerFindFileA");
    real_VerFindFileW = (pfnVerFindFileW)GetProcAddress(g_hRealVersion, "VerFindFileW");
    real_VerInstallFileA = (pfnVerInstallFileA)GetProcAddress(g_hRealVersion, "VerInstallFileA");
    real_VerInstallFileW = (pfnVerInstallFileW)GetProcAddress(g_hRealVersion, "VerInstallFileW");
    real_VerLanguageNameA = (pfnVerLanguageNameA)GetProcAddress(g_hRealVersion, "VerLanguageNameA");
    real_VerLanguageNameW = (pfnVerLanguageNameW)GetProcAddress(g_hRealVersion, "VerLanguageNameW");
    real_VerQueryValueA = (pfnVerQueryValueA)GetProcAddress(g_hRealVersion, "VerQueryValueA");
    real_VerQueryValueW = (pfnVerQueryValueW)GetProcAddress(g_hRealVersion, "VerQueryValueW");
  }

  // Initialize SanQi Capture core + hooks
  add_hooks();

  // Apply stealth (PEB unlink, PE wipe, NtQuery hook, Vulkan layer hide)
  ApplyStealthMeasures(g_hSelf);

  InterlockedExchange(&g_initOnce, 2);
}

// ============================================================================
// Forwarded exports
// ============================================================================

extern "C" {

BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d)
{ LazyInit(); return real_GetFileVersionInfoA ? real_GetFileVersionInfoA(a,b,c,d) : FALSE; }

BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d)
{ LazyInit(); return real_GetFileVersionInfoW ? real_GetFileVersionInfoW(a,b,c,d) : FALSE; }

DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b)
{ LazyInit(); return real_GetFileVersionInfoSizeA ? real_GetFileVersionInfoSizeA(a,b) : 0; }

DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b)
{ LazyInit(); return real_GetFileVersionInfoSizeW ? real_GetFileVersionInfoSizeW(a,b) : 0; }

BOOL WINAPI Proxy_GetFileVersionInfoExA(DWORD f, LPCSTR a, DWORD b, DWORD c, LPVOID d)
{ LazyInit(); return real_GetFileVersionInfoExA ? real_GetFileVersionInfoExA(f,a,b,c,d) : FALSE; }

BOOL WINAPI Proxy_GetFileVersionInfoExW(DWORD f, LPCWSTR a, DWORD b, DWORD c, LPVOID d)
{ LazyInit(); return real_GetFileVersionInfoExW ? real_GetFileVersionInfoExW(f,a,b,c,d) : FALSE; }

DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(DWORD f, LPCSTR a, LPDWORD b)
{ LazyInit(); return real_GetFileVersionInfoSizeExA ? real_GetFileVersionInfoSizeExA(f,a,b) : 0; }

DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(DWORD f, LPCWSTR a, LPDWORD b)
{ LazyInit(); return real_GetFileVersionInfoSizeExW ? real_GetFileVersionInfoSizeExW(f,a,b) : 0; }

DWORD WINAPI Proxy_VerFindFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h)
{ LazyInit(); return real_VerFindFileA ? real_VerFindFileA(a,b,c,d,e,f,g,h) : 0; }

DWORD WINAPI Proxy_VerFindFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h)
{ LazyInit(); return real_VerFindFileW ? real_VerFindFileW(a,b,c,d,e,f,g,h) : 0; }

DWORD WINAPI Proxy_VerInstallFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPCSTR f, LPSTR g, PUINT h)
{ LazyInit(); return real_VerInstallFileA ? real_VerInstallFileA(a,b,c,d,e,f,g,h) : 0; }

DWORD WINAPI Proxy_VerInstallFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPCWSTR f, LPWSTR g, PUINT h)
{ LazyInit(); return real_VerInstallFileW ? real_VerInstallFileW(a,b,c,d,e,f,g,h) : 0; }

DWORD WINAPI Proxy_VerLanguageNameA(DWORD a, LPSTR b, DWORD c)
{ LazyInit(); return real_VerLanguageNameA ? real_VerLanguageNameA(a,b,c) : 0; }

DWORD WINAPI Proxy_VerLanguageNameW(DWORD a, LPWSTR b, DWORD c)
{ LazyInit(); return real_VerLanguageNameW ? real_VerLanguageNameW(a,b,c) : 0; }

BOOL WINAPI Proxy_VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID *c, PUINT d)
{ LazyInit(); return real_VerQueryValueA ? real_VerQueryValueA(a,b,c,d) : FALSE; }

BOOL WINAPI Proxy_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID *c, PUINT d)
{ LazyInit(); return real_VerQueryValueW ? real_VerQueryValueW(a,b,c,d) : FALSE; }

}    // extern "C"

// ============================================================================
// DllMain
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  if(ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    DisableThreadLibraryCalls(hModule);
    g_hSelf = hModule;
    // No initialization here — LazyInit fires on first API call.
  }
  else if(ul_reason_for_call == DLL_PROCESS_DETACH)
  {
    if(g_hRealVersion)
    {
      FreeLibrary(g_hRealVersion);
      g_hRealVersion = NULL;
    }
  }
  return TRUE;
}
