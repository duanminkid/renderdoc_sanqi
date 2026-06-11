#include <windows.h>
#include <d3dkmthk.h>
#include <stdint.h>

typedef void(__cdecl *PFN_SetCaptureFile)(const char *);
typedef void(__cdecl *PFN_SetDebugLogFile)(const char *);
typedef void(__cdecl *PFN_SetCaptureOptions)(void *);
typedef void(__cdecl *PFN_GetTargetControlIdent)(uint32_t *);

static HMODULE realD3D11 = NULL;
static HMODULE systemLoad = NULL;
static volatile LONG initState = 0;

extern "C" __declspec(dllexport) const char SQC_D3D11_PROXY_PAYLOAD_MARKER[] =
    "SQC_D3D11_PROXY_PAYLOAD_V1";

static void Trace(const char *msg)
{
  char path[MAX_PATH] = {};
  GetTempPathA(MAX_PATH, path);
  lstrcatA(path, "sqc_d3d11_proxy.txt");

  HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(h != INVALID_HANDLE_VALUE)
  {
    DWORD written = 0;
    WriteFile(h, msg, (DWORD)lstrlenA(msg), &written, NULL);
    CloseHandle(h);
  }

  OutputDebugStringA(msg);
}

static void WriteIdent(uint32_t ident)
{
  char identFile[MAX_PATH] = {};
  DWORD len = GetEnvironmentVariableA("SQC_PROXY_IDENT_FILE", identFile, MAX_PATH);
  if(len == 0 || len >= MAX_PATH)
    return;

  HANDLE h = CreateFileA(identFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(h == INVALID_HANDLE_VALUE)
    return;

  char buf[64] = {};
  wsprintfA(buf, "%u", ident);
  DWORD written = 0;
  WriteFile(h, buf, (DWORD)lstrlenA(buf), &written, NULL);
  CloseHandle(h);
}

static void TraceLastError(const char *prefix)
{
  char msg[256] = {};
  wsprintfA(msg, "%s err=%u\r\n", prefix, GetLastError());
  Trace(msg);
}

static void ConfigureSystemLoad()
{
  char value[32768] = {};

  PFN_SetCaptureFile setCaptureFile =
      (PFN_SetCaptureFile)GetProcAddress(systemLoad, "INTERNAL_SetCaptureFile");
  if(setCaptureFile)
  {
    DWORD len = GetEnvironmentVariableA("SQC_PROXY_CAPTURE_FILE", value, sizeof(value));
    if(len > 0 && len < sizeof(value))
      setCaptureFile(value);
  }
  else
  {
    Trace("proxy missing INTERNAL_SetCaptureFile\r\n");
  }

  PFN_SetDebugLogFile setDebugLogFile =
      (PFN_SetDebugLogFile)GetProcAddress(systemLoad, "INTERNAL_SetDebugLogFile");
  if(setDebugLogFile)
  {
    DWORD len = GetEnvironmentVariableA("SQC_PROXY_DEBUG_LOG", value, sizeof(value));
    if(len > 0 && len < sizeof(value))
      setDebugLogFile(value);
  }
  else
  {
    Trace("proxy missing INTERNAL_SetDebugLogFile\r\n");
  }

  PFN_SetCaptureOptions setCaptureOptions =
      (PFN_SetCaptureOptions)GetProcAddress(systemLoad, "INTERNAL_SetCaptureOptions");
  if(setCaptureOptions)
  {
    DWORD len = GetEnvironmentVariableA("SQC_PROXY_CAPTURE_OPTS", value, sizeof(value));
    if(len > 0 && len < sizeof(value))
    {
      unsigned char opts[256] = {};
      size_t bytes = len / 2;
      if(bytes > sizeof(opts))
        bytes = sizeof(opts);

      for(size_t i = 0; i < bytes; i++)
      {
        unsigned char hi = (unsigned char)(value[i * 2 + 0] - 'a');
        unsigned char lo = (unsigned char)(value[i * 2 + 1] - 'a');
        opts[i] = (unsigned char)((hi << 4) | lo);
      }

      setCaptureOptions(opts);
    }
  }
  else
  {
    Trace("proxy missing INTERNAL_SetCaptureOptions\r\n");
  }

  PFN_GetTargetControlIdent getIdent =
      (PFN_GetTargetControlIdent)GetProcAddress(systemLoad, "INTERNAL_GetTargetControlIdent");
  if(getIdent)
  {
    uint32_t ident = 0;
    getIdent(&ident);
    char msg[128] = {};
    wsprintfA(msg, "proxy target control ident=%u\r\n", ident);
    Trace(msg);
    WriteIdent(ident);
  }
  else
  {
    Trace("proxy missing INTERNAL_GetTargetControlIdent\r\n");
  }
}

static void Init()
{
  LONG prev = InterlockedCompareExchange(&initState, 1, 0);
  if(prev == 2)
    return;
  if(prev == 1)
  {
    while(InterlockedCompareExchange(&initState, 2, 2) != 2)
      Sleep(1);
    return;
  }

  wchar_t systemPath[MAX_PATH] = {};
  GetSystemDirectoryW(systemPath, MAX_PATH);
  lstrcatW(systemPath, L"\\d3d11.dll");
  realD3D11 = LoadLibraryW(systemPath);
  if(realD3D11)
    Trace("proxy loaded real d3d11\r\n");
  else
    TraceLastError("proxy failed to load real d3d11");

  char loadPath[MAX_PATH] = {};
  DWORD len = GetEnvironmentVariableA("SQC_PROXY_SYSTEM_LOAD", loadPath, MAX_PATH);
  if(len > 0 && len < MAX_PATH)
  {
    systemLoad = LoadLibraryA(loadPath);
    if(systemLoad)
    {
      Trace("proxy loaded system_load\r\n");
      ConfigureSystemLoad();
    }
    else
    {
      TraceLastError("proxy failed to load system_load");
    }
  }
  else
  {
    Trace("proxy missing SQC_PROXY_SYSTEM_LOAD\r\n");
  }

  InterlockedExchange(&initState, 2);
}

static DWORD WINAPI ProxyInitThread(void *)
{
  Trace("proxy init thread begin\r\n");
  Init();
  Trace("proxy init thread end\r\n");
  return 0;
}

static FARPROC RealProc(const char *name)
{
  Init();
  return realD3D11 ? GetProcAddress(realD3D11, name) : NULL;
}

#define FORWARD_HRESULT(name, args, callargs)        \
  extern "C" HRESULT WINAPI Proxy_##name args        \
  {                                                  \
    typedef HRESULT(WINAPI *PFN) args;               \
    PFN fn = (PFN)RealProc(#name);                   \
    return fn ? fn callargs : E_FAIL;                \
  }

#define FORWARD_INT(name)                            \
  extern "C" int WINAPI Proxy_##name()               \
  {                                                  \
    typedef int(WINAPI *PFN)();                      \
    PFN fn = (PFN)RealProc(#name);                   \
    return fn ? fn() : 0;                            \
  }

#define SQC_STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)

#define FORWARD_NTSTATUS_PTR(name, type)             \
  extern "C" NTSTATUS WINAPI Proxy_##name(type *a)   \
  {                                                  \
    typedef NTSTATUS(WINAPI *PFN)(type *);           \
    PFN fn = (PFN)RealProc(#name);                   \
    return fn ? fn(a) : SQC_STATUS_NOT_IMPLEMENTED;  \
  }

#define FORWARD_NTSTATUS_CONST_PTR(name, type)                 \
  extern "C" NTSTATUS WINAPI Proxy_##name(const type *a)       \
  {                                                            \
    typedef NTSTATUS(WINAPI *PFN)(const type *);               \
    PFN fn = (PFN)RealProc(#name);                             \
    return fn ? fn(a) : SQC_STATUS_NOT_IMPLEMENTED;            \
  }

#define FORWARD_INT_PTR(name)                                  \
  extern "C" int WINAPI Proxy_##name(void *a)                  \
  {                                                            \
    typedef int(WINAPI *PFN)(void *);                          \
    PFN fn = (PFN)RealProc(#name);                             \
    return fn ? fn(a) : (int)SQC_STATUS_NOT_IMPLEMENTED;       \
  }

extern "C" HRESULT WINAPI Proxy_D3D11CreateDevice(
    void *pAdapter, int DriverType, HMODULE Software, UINT Flags, const void *pFeatureLevels,
    UINT FeatureLevels, UINT SDKVersion, void **ppDevice, void *pFeatureLevel,
    void **ppImmediateContext)
{
  typedef HRESULT(WINAPI *PFN)(void *, int, HMODULE, UINT, const void *, UINT, UINT, void **,
                               void *, void **);
  PFN fn = (PFN)RealProc("D3D11CreateDevice");
  HRESULT hr = fn ? fn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                       SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext)
                  : E_FAIL;
  char msg[256] = {};
  wsprintfA(msg, "proxy D3D11CreateDevice hr=0x%08X device=%p ctx=%p\r\n", (unsigned int)hr,
            ppDevice ? *ppDevice : NULL, ppImmediateContext ? *ppImmediateContext : NULL);
  Trace(msg);
  return hr;
}

extern "C" HRESULT WINAPI Proxy_D3D11CreateDeviceAndSwapChain(
    void *pAdapter, int DriverType, HMODULE Software, UINT Flags, const void *pFeatureLevels,
    UINT FeatureLevels, UINT SDKVersion, const void *pSwapChainDesc, void **ppSwapChain,
    void **ppDevice, void *pFeatureLevel, void **ppImmediateContext)
{
  typedef HRESULT(WINAPI *PFN)(void *, int, HMODULE, UINT, const void *, UINT, UINT, const void *,
                               void **, void **, void *, void **);
  PFN fn = (PFN)RealProc("D3D11CreateDeviceAndSwapChain");
  HRESULT hr = fn ? fn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                       SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel,
                       ppImmediateContext)
                  : E_FAIL;
  char msg[256] = {};
  wsprintfA(msg, "proxy D3D11CreateDeviceAndSwapChain hr=0x%08X device=%p swap=%p ctx=%p\r\n",
            (unsigned int)hr, ppDevice ? *ppDevice : NULL, ppSwapChain ? *ppSwapChain : NULL,
            ppImmediateContext ? *ppImmediateContext : NULL);
  Trace(msg);
  return hr;
}

FORWARD_HRESULT(D3D11CoreCreateDevice,
                (void *a, void *b, void *c, UINT d, const void *e, UINT f, UINT g, void **h,
                 void *i),
                (a, b, c, d, e, f, g, h, i))
FORWARD_HRESULT(D3D11CoreCreateLayeredDevice, (void *a, UINT b, void *c, void *d, void **e),
                (a, b, c, d, e))

extern "C" SIZE_T WINAPI Proxy_D3D11CoreGetLayeredDeviceSize(void *a, UINT b)
{
  typedef SIZE_T(WINAPI *PFN)(void *, UINT);
  PFN fn = (PFN)RealProc("D3D11CoreGetLayeredDeviceSize");
  return fn ? fn(a, b) : 0;
}

FORWARD_HRESULT(D3D11CoreRegisterLayers, (void *a, UINT b), (a, b))
FORWARD_HRESULT(D3D11CreateDeviceForD3D12,
                (void *a, void *b, UINT c, const void *d, UINT e, void **f, void *g, void **h),
                (a, b, c, d, e, f, g, h))
FORWARD_HRESULT(D3D11On12CreateDevice,
                (void *a, UINT b, const void *c, UINT d, void **e, UINT f, UINT g, void **h,
                 void **i, void *j),
                (a, b, c, d, e, f, g, h, i, j))
FORWARD_HRESULT(CreateDirect3D11DeviceFromDXGIDevice, (void *a, void **b), (a, b))
FORWARD_HRESULT(CreateDirect3D11SurfaceFromDXGISurface, (void *a, void **b), (a, b))

extern "C" HRESULT WINAPI Proxy_EnableFeatureLevelUpgrade()
{
  typedef HRESULT(WINAPI *PFN)();
  PFN fn = (PFN)RealProc("EnableFeatureLevelUpgrade");
  return fn ? fn() : E_FAIL;
}

FORWARD_NTSTATUS_CONST_PTR(D3DKMTCloseAdapter, D3DKMT_CLOSEADAPTER)
FORWARD_NTSTATUS_PTR(D3DKMTCreateAllocation, D3DKMT_CREATEALLOCATION)
FORWARD_NTSTATUS_PTR(D3DKMTCreateContext, D3DKMT_CREATECONTEXT)
FORWARD_NTSTATUS_PTR(D3DKMTCreateDevice, D3DKMT_CREATEDEVICE)
FORWARD_NTSTATUS_PTR(D3DKMTCreateSynchronizationObject, D3DKMT_CREATESYNCHRONIZATIONOBJECT)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTDestroyAllocation, D3DKMT_DESTROYALLOCATION)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTDestroyContext, D3DKMT_DESTROYCONTEXT)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTDestroyDevice, D3DKMT_DESTROYDEVICE)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTDestroySynchronizationObject, D3DKMT_DESTROYSYNCHRONIZATIONOBJECT)
FORWARD_NTSTATUS_PTR(D3DKMTGetContextSchedulingPriority, D3DKMT_GETCONTEXTSCHEDULINGPRIORITY)
FORWARD_NTSTATUS_PTR(D3DKMTGetDisplayModeList, D3DKMT_GETDISPLAYMODELIST)
FORWARD_NTSTATUS_PTR(D3DKMTGetMultisampleMethodList, D3DKMT_GETMULTISAMPLEMETHODLIST)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTGetRuntimeData, D3DKMT_GETRUNTIMEDATA)
FORWARD_NTSTATUS_PTR(D3DKMTGetSharedPrimaryHandle, D3DKMT_GETSHAREDPRIMARYHANDLE)
FORWARD_NTSTATUS_PTR(D3DKMTLock, D3DKMT_LOCK)
FORWARD_NTSTATUS_PTR(D3DKMTPresent, D3DKMT_PRESENT)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTQueryAllocationResidency, D3DKMT_QUERYALLOCATIONRESIDENCY)
FORWARD_NTSTATUS_PTR(D3DKMTRender, D3DKMT_RENDER)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTSetAllocationPriority, D3DKMT_SETALLOCATIONPRIORITY)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTSetContextSchedulingPriority, D3DKMT_SETCONTEXTSCHEDULINGPRIORITY)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTSetDisplayMode, D3DKMT_SETDISPLAYMODE)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTSetDisplayPrivateDriverFormat,
                           D3DKMT_SETDISPLAYPRIVATEDRIVERFORMAT)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTSetGammaRamp, D3DKMT_SETGAMMARAMP)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTSetVidPnSourceOwner, D3DKMT_SETVIDPNSOURCEOWNER)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTSignalSynchronizationObject, D3DKMT_SIGNALSYNCHRONIZATIONOBJECT)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTUnlock, D3DKMT_UNLOCK)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTWaitForSynchronizationObject, D3DKMT_WAITFORSYNCHRONIZATIONOBJECT)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTWaitForVerticalBlankEvent, D3DKMT_WAITFORVERTICALBLANKEVENT)
FORWARD_INT_PTR(OpenAdapter10)
FORWARD_INT_PTR(OpenAdapter10_2)

FORWARD_NTSTATUS_CONST_PTR(D3DKMTQueryAdapterInfo, D3DKMT_QUERYADAPTERINFO)
FORWARD_NTSTATUS_CONST_PTR(D3DKMTEscape, D3DKMT_ESCAPE)
FORWARD_NTSTATUS_PTR(D3DKMTGetDeviceState, D3DKMT_GETDEVICESTATE)
FORWARD_NTSTATUS_PTR(D3DKMTOpenAdapterFromHdc, D3DKMT_OPENADAPTERFROMHDC)
FORWARD_NTSTATUS_PTR(D3DKMTOpenResource, D3DKMT_OPENRESOURCE)
FORWARD_NTSTATUS_PTR(D3DKMTQueryResourceInfo, D3DKMT_QUERYRESOURCEINFO)

extern "C" int WINAPI Proxy_D3DPerformance_BeginEvent(UINT64, const wchar_t *) { return 0; }
extern "C" int WINAPI Proxy_D3DPerformance_EndEvent() { return 0; }
extern "C" UINT WINAPI Proxy_D3DPerformance_GetStatus() { return 0; }
extern "C" int WINAPI Proxy_D3DPerformance_SetMarker(UINT64, const wchar_t *) { return 0; }

extern "C" LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam)
{
  return CallNextHookEx(0, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hinst, DWORD reason, LPVOID)
{
  if(reason == DLL_PROCESS_ATTACH)
  {
    Trace("d3d11 proxy attach\r\n");
    DisableThreadLibraryCalls(hinst);

    HANDLE thread = CreateThread(NULL, 0, ProxyInitThread, NULL, 0, NULL);
    if(thread)
      CloseHandle(thread);
    else
      TraceLastError("proxy failed to create init thread");
  }

  return TRUE;
}
