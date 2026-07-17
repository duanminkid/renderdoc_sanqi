#include <windows.h>
#include <d3dkmthk.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <string.h>

typedef void(__cdecl *PFN_SetCaptureFile)(const char *);
typedef void(__cdecl *PFN_SetDebugLogFile)(const char *);
typedef void(__cdecl *PFN_SetCaptureOptions)(void *);
typedef void(__cdecl *PFN_GetTargetControlIdent)(uint32_t *);
typedef HRESULT(WINAPI *PFN_D3D11_CREATE_DEVICE)(void *, int, HMODULE, UINT, const void *, UINT,
                                                 UINT, void **, void *, void **);
typedef HRESULT(WINAPI *PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)(
    void *, int, HMODULE, UINT, const void *, UINT, UINT, const void *, void **, void **, void *,
    void **);
typedef HRESULT(WINAPI *PFN_D3D11_WRAP_CREATED_DEVICE)(int, UINT, const void *, UINT, UINT,
                                                       void **, void **, void **, HWND);
typedef HRESULT(WINAPI *PFN_CREATE_DXGI_FACTORY)(REFIID, void **);
typedef HRESULT(WINAPI *PFN_CREATE_DXGI_FACTORY2)(UINT, REFIID, void **);
typedef HRESULT(WINAPI *PFN_DXGI_WRAP_FACTORY)(REFIID, void **);
typedef HRESULT(WINAPI *PFN_DXGI_HOOK_FACTORY_SWAPCHAIN_CREATES)(IUnknown *);
typedef FARPROC(WINAPI *PFN_GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *PFN_LOADLIBRARYA)(LPCSTR);
typedef HMODULE(WINAPI *PFN_LOADLIBRARYW)(LPCWSTR);
typedef HMODULE(WINAPI *PFN_LOADLIBRARYEXA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE(WINAPI *PFN_LOADLIBRARYEXW)(LPCWSTR, HANDLE, DWORD);

extern "C" HRESULT WINAPI Proxy_D3D11CreateDevice(void *pAdapter, int DriverType, HMODULE Software,
                                                  UINT Flags, const void *pFeatureLevels,
                                                  UINT FeatureLevels, UINT SDKVersion,
                                                  void **ppDevice, void *pFeatureLevel,
                                                  void **ppImmediateContext);
extern "C" HRESULT WINAPI Proxy_D3D11CreateDeviceAndSwapChain(
    void *pAdapter, int DriverType, HMODULE Software, UINT Flags, const void *pFeatureLevels,
    UINT FeatureLevels, UINT SDKVersion, const void *pSwapChainDesc, void **ppSwapChain,
    void **ppDevice, void *pFeatureLevel, void **ppImmediateContext);
extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory(REFIID riid, void **ppFactory);
extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory1(REFIID riid, void **ppFactory);
extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory2(UINT Flags, REFIID riid, void **ppFactory);
extern "C" FARPROC WINAPI Proxy_GetProcAddress(HMODULE module, LPCSTR name);
extern "C" HMODULE WINAPI Proxy_LoadLibraryA(LPCSTR name);
extern "C" HMODULE WINAPI Proxy_LoadLibraryW(LPCWSTR name);
extern "C" HMODULE WINAPI Proxy_LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags);
extern "C" HMODULE WINAPI Proxy_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags);

static HMODULE realD3D11 = NULL;
static HMODULE realDXGI = NULL;
static HMODULE systemLoad = NULL;
static HMODULE proxySelf = NULL;
static PFN_GETPROCADDRESS realGetProcAddress = NULL;
static PFN_LOADLIBRARYA realLoadLibraryA = NULL;
static PFN_LOADLIBRARYW realLoadLibraryW = NULL;
static PFN_LOADLIBRARYEXA realLoadLibraryExA = NULL;
static PFN_LOADLIBRARYEXW realLoadLibraryExW = NULL;
static volatile LONG initState = 0;
static volatile LONG captureLoadState = 0;
static volatile LONG patchedModulesLock = 0;
static volatile LONG runtimeModulePatchCount = 0;
static volatile LONG d3d11ShadowReady = 0;
static HMODULE patchedModules[256] = {};

static void TraceLastError(const char *prefix);

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

static bool EnvEnabled(const char *name)
{
  char value[16] = {};
  DWORD len = GetEnvironmentVariableA(name, value, sizeof(value));
  return len > 0 && lstrcmpiA(value, "0") != 0 && lstrcmpiA(value, "false") != 0 &&
         lstrcmpiA(value, "off") != 0;
}

static bool BootstrapOnly()
{
  if(EnvEnabled("SQC_PROXY_BOOTSTRAP_ONLY"))
    return true;

  char loadPath[MAX_PATH] = {};
  DWORD len = GetEnvironmentVariableA("SQC_PROXY_SYSTEM_LOAD", loadPath, MAX_PATH);
  return len > 0 && len < MAX_PATH && lstrcmpiA(loadPath, "__bootstrap_only__") == 0;
}

static bool DeferredCapture()
{
  if(EnvEnabled("SQC_PROXY_DEFER_CAPTURE_LOAD"))
    return true;

  char flags[128] = {};
  DWORD len = GetEnvironmentVariableA("SQC_PROXY_FLAGS", flags, sizeof(flags));
  return len > 0 && len < sizeof(flags) && strstr(flags, "defer_capture") != NULL;
}

static bool IsD3D11CreateName(const char *name)
{
  return name && (lstrcmpiA(name, "D3D11CreateDevice") == 0 ||
                  lstrcmpiA(name, "D3D11CreateDeviceAndSwapChain") == 0);
}

static bool IsDXGIFactoryName(const char *name)
{
  return name && (lstrcmpiA(name, "CreateDXGIFactory") == 0 ||
                  lstrcmpiA(name, "CreateDXGIFactory1") == 0 ||
                  lstrcmpiA(name, "CreateDXGIFactory2") == 0);
}

static bool IsYuanShenProcess()
{
  wchar_t curFile[MAX_PATH] = {};
  if(GetModuleFileNameW(NULL, curFile, MAX_PATH) == 0)
    return false;

  const wchar_t *base = curFile;
  for(const wchar_t *p = curFile; *p; p++)
  {
    if(*p == L'\\' || *p == L'/')
      base = p + 1;
  }

  return lstrcmpiW(base, L"YuanShen.exe") == 0;
}

static const char *BaseNameA(const char *path)
{
  const char *base = path;
  if(path == NULL)
    return NULL;

  for(const char *p = path; *p; p++)
  {
    if(*p == '\\' || *p == '/')
      base = p + 1;
  }

  return base;
}

static const wchar_t *BaseNameW(const wchar_t *path)
{
  const wchar_t *base = path;
  if(path == NULL)
    return NULL;

  for(const wchar_t *p = path; *p; p++)
  {
    if(*p == L'\\' || *p == L'/')
      base = p + 1;
  }

  return base;
}

static bool IsD3D11PathA(const char *path)
{
  const char *base = BaseNameA(path);
  return base && lstrcmpiA(base, "d3d11.dll") == 0;
}

static bool IsDXGIPathA(const char *path)
{
  const char *base = BaseNameA(path);
  return base && lstrcmpiA(base, "dxgi.dll") == 0;
}

static bool IsD3D11PathW(const wchar_t *path)
{
  const wchar_t *base = BaseNameW(path);
  return base && lstrcmpiW(base, L"d3d11.dll") == 0;
}

static bool IsDXGIPathW(const wchar_t *path)
{
  const wchar_t *base = BaseNameW(path);
  return base && lstrcmpiW(base, L"dxgi.dll") == 0;
}

static bool IsD3D11Module(HMODULE module)
{
  if(module == NULL)
    return false;

  if(module == realD3D11)
    return true;

  char modulePath[MAX_PATH] = {};
  if(GetModuleFileNameA(module, modulePath, MAX_PATH) == 0)
    return false;

  return IsD3D11PathA(modulePath);
}

static bool IsDXGIModule(HMODULE module)
{
  if(module == NULL)
    return false;

  if(module == realDXGI)
    return true;

  char modulePath[MAX_PATH] = {};
  if(GetModuleFileNameA(module, modulePath, MAX_PATH) == 0)
    return false;

  return IsDXGIPathA(modulePath);
}

static bool IsWindowsSystemModule(HMODULE module)
{
  char modulePath[MAX_PATH] = {};
  char windowsPath[MAX_PATH] = {};
  if(GetModuleFileNameA(module, modulePath, MAX_PATH) == 0 ||
     GetWindowsDirectoryA(windowsPath, MAX_PATH) == 0)
    return false;

  size_t winLen = lstrlenA(windowsPath);
  return winLen > 0 && _strnicmp(modulePath, windowsPath, winLen) == 0 &&
         (modulePath[winLen] == '\\' || modulePath[winLen] == '/');
}

static bool MarkModuleForPatch(HMODULE module)
{
  while(InterlockedCompareExchange(&patchedModulesLock, 1, 0) != 0)
    Sleep(0);

  bool shouldPatch = true;
  int freeSlot = -1;
  for(size_t i = 0; i < sizeof(patchedModules) / sizeof(patchedModules[0]); i++)
  {
    if(patchedModules[i] == module)
    {
      shouldPatch = false;
      break;
    }

    if(patchedModules[i] == NULL && freeSlot < 0)
      freeSlot = (int)i;
  }

  if(shouldPatch && freeSlot >= 0)
    patchedModules[freeSlot] = module;

  InterlockedExchange(&patchedModulesLock, 0);
  return shouldPatch && freeSlot >= 0;
}

static bool PatchImportThunk(void **iatEntry, void *replacement, const char *name)
{
  DWORD oldProtect = 0;
  if(!VirtualProtect(iatEntry, sizeof(void *), PAGE_READWRITE, &oldProtect))
    return false;

  *iatEntry = replacement;

  DWORD unused = 0;
  VirtualProtect(iatEntry, sizeof(void *), oldProtect, &unused);
  FlushInstructionCache(GetCurrentProcess(), iatEntry, sizeof(void *));

  char msg[256] = {};
  wsprintfA(msg, "proxy patched IAT %s entry=%p replacement=%p\r\n", name, iatEntry, replacement);
  Trace(msg);
  return true;
}

static uint32_t PatchModuleD3D11IAT(HMODULE module, const char *label)
{
  if(module == NULL)
    return 0;

  unsigned char *base = (unsigned char *)module;
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
  if(dos->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
  if(nt->Signature != IMAGE_NT_SIGNATURE)
    return 0;

  IMAGE_DATA_DIRECTORY importsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if(importsDir.VirtualAddress == 0 || importsDir.Size == 0)
  {
    char msg[160] = {};
    wsprintfA(msg, "proxy module has no import table %s\r\n", label ? label : "");
    Trace(msg);
    return 0;
  }

  PIMAGE_IMPORT_DESCRIPTOR imports =
      (PIMAGE_IMPORT_DESCRIPTOR)(base + importsDir.VirtualAddress);

  uint32_t patched = 0;
  for(; imports->Name != 0; imports++)
  {
    const char *dllName = (const char *)(base + imports->Name);
    if(lstrcmpiA(dllName, "d3d11.dll") != 0)
      continue;

    IMAGE_THUNK_DATA *origThunk = imports->OriginalFirstThunk
                                      ? (IMAGE_THUNK_DATA *)(base + imports->OriginalFirstThunk)
                                      : (IMAGE_THUNK_DATA *)(base + imports->FirstThunk);
    IMAGE_THUNK_DATA *iatThunk = (IMAGE_THUNK_DATA *)(base + imports->FirstThunk);

    for(; origThunk->u1.AddressOfData != 0; origThunk++, iatThunk++)
    {
      if(IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal))
        continue;

      PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)(base + origThunk->u1.AddressOfData);
      const char *funcName = (const char *)byName->Name;
      if(!IsD3D11CreateName(funcName))
        continue;

      void *replacement = lstrcmpiA(funcName, "D3D11CreateDevice") == 0
                              ? (void *)&Proxy_D3D11CreateDevice
                              : (void *)&Proxy_D3D11CreateDeviceAndSwapChain;

      if(PatchImportThunk((void **)&iatThunk->u1.Function, replacement, funcName))
        patched++;
    }
  }

  char msg[192] = {};
  wsprintfA(msg, "proxy D3D11 IAT patch count=%u module=%p %s\r\n", patched, module,
            label ? label : "");
  Trace(msg);
  return patched;
}

static uint32_t PatchModuleDXGIIAT(HMODULE module, const char *label)
{
  if(module == NULL)
    return 0;

  unsigned char *base = (unsigned char *)module;
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
  if(dos->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
  if(nt->Signature != IMAGE_NT_SIGNATURE)
    return 0;

  IMAGE_DATA_DIRECTORY importsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if(importsDir.VirtualAddress == 0 || importsDir.Size == 0)
    return 0;

  PIMAGE_IMPORT_DESCRIPTOR imports =
      (PIMAGE_IMPORT_DESCRIPTOR)(base + importsDir.VirtualAddress);

  uint32_t patched = 0;
  for(; imports->Name != 0; imports++)
  {
    const char *dllName = (const char *)(base + imports->Name);
    if(lstrcmpiA(dllName, "dxgi.dll") != 0)
      continue;

    IMAGE_THUNK_DATA *origThunk = imports->OriginalFirstThunk
                                      ? (IMAGE_THUNK_DATA *)(base + imports->OriginalFirstThunk)
                                      : (IMAGE_THUNK_DATA *)(base + imports->FirstThunk);
    IMAGE_THUNK_DATA *iatThunk = (IMAGE_THUNK_DATA *)(base + imports->FirstThunk);

    for(; origThunk->u1.AddressOfData != 0; origThunk++, iatThunk++)
    {
      if(IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal))
        continue;

      PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)(base + origThunk->u1.AddressOfData);
      const char *funcName = (const char *)byName->Name;
      if(!IsDXGIFactoryName(funcName))
        continue;

      void *replacement = NULL;
      if(lstrcmpiA(funcName, "CreateDXGIFactory") == 0)
        replacement = (void *)&Proxy_CreateDXGIFactory;
      else if(lstrcmpiA(funcName, "CreateDXGIFactory1") == 0)
        replacement = (void *)&Proxy_CreateDXGIFactory1;
      else
        replacement = (void *)&Proxy_CreateDXGIFactory2;

      if(PatchImportThunk((void **)&iatThunk->u1.Function, replacement, funcName))
        patched++;
    }
  }

  char msg[192] = {};
  wsprintfA(msg, "proxy DXGI IAT patch count=%u module=%p %s\r\n", patched, module,
            label ? label : "");
  Trace(msg);
  return patched;
}

static void PatchMainModuleD3D11IAT()
{
  PatchModuleD3D11IAT(GetModuleHandleW(NULL), "main");
  if(IsYuanShenProcess())
    Trace("proxy skip main DXGI IAT patch for yuanshen\r\n");
  else
    PatchModuleDXGIIAT(GetModuleHandleW(NULL), "main");
}

static uint32_t PatchModuleLoaderIAT(HMODULE module, const char *label)
{
  if(module == NULL)
    return 0;

  unsigned char *base = (unsigned char *)module;
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
  if(dos->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
  if(nt->Signature != IMAGE_NT_SIGNATURE)
    return 0;

  IMAGE_DATA_DIRECTORY importsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if(importsDir.VirtualAddress == 0 || importsDir.Size == 0)
    return 0;

  PIMAGE_IMPORT_DESCRIPTOR imports =
      (PIMAGE_IMPORT_DESCRIPTOR)(base + importsDir.VirtualAddress);

  uint32_t patched = 0;
  for(; imports->Name != 0; imports++)
  {
    IMAGE_THUNK_DATA *origThunk = imports->OriginalFirstThunk
                                      ? (IMAGE_THUNK_DATA *)(base + imports->OriginalFirstThunk)
                                      : (IMAGE_THUNK_DATA *)(base + imports->FirstThunk);
    IMAGE_THUNK_DATA *iatThunk = (IMAGE_THUNK_DATA *)(base + imports->FirstThunk);

    for(; origThunk->u1.AddressOfData != 0; origThunk++, iatThunk++)
    {
      if(IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal))
        continue;

      PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)(base + origThunk->u1.AddressOfData);
      const char *funcName = (const char *)byName->Name;
      void *replacement = NULL;

      if(lstrcmpiA(funcName, "GetProcAddress") == 0)
      {
        if(realGetProcAddress == NULL)
          realGetProcAddress = (PFN_GETPROCADDRESS)iatThunk->u1.Function;
        replacement = (void *)&Proxy_GetProcAddress;
      }
      else if(lstrcmpiA(funcName, "LoadLibraryA") == 0)
      {
        if(realLoadLibraryA == NULL)
          realLoadLibraryA = (PFN_LOADLIBRARYA)iatThunk->u1.Function;
        replacement = (void *)&Proxy_LoadLibraryA;
      }
      else if(lstrcmpiA(funcName, "LoadLibraryW") == 0)
      {
        if(realLoadLibraryW == NULL)
          realLoadLibraryW = (PFN_LOADLIBRARYW)iatThunk->u1.Function;
        replacement = (void *)&Proxy_LoadLibraryW;
      }
      else if(lstrcmpiA(funcName, "LoadLibraryExA") == 0)
      {
        if(realLoadLibraryExA == NULL)
          realLoadLibraryExA = (PFN_LOADLIBRARYEXA)iatThunk->u1.Function;
        replacement = (void *)&Proxy_LoadLibraryExA;
      }
      else if(lstrcmpiA(funcName, "LoadLibraryExW") == 0)
      {
        if(realLoadLibraryExW == NULL)
          realLoadLibraryExW = (PFN_LOADLIBRARYEXW)iatThunk->u1.Function;
        replacement = (void *)&Proxy_LoadLibraryExW;
      }

      if(replacement && (void *)iatThunk->u1.Function != replacement &&
         PatchImportThunk((void **)&iatThunk->u1.Function, replacement, funcName))
        patched++;
    }
  }

  char msg[192] = {};
  wsprintfA(msg, "proxy loader IAT patch count=%u module=%p %s\r\n", patched, module,
            label ? label : "");
  Trace(msg);
  return patched;
}

static void PatchMainModuleLoaderIAT()
{
  PatchModuleLoaderIAT(GetModuleHandleW(NULL), "main");
}

static void PatchLoadedModuleIATs(HMODULE module, const char *label)
{
  if(module == NULL || module == realD3D11 || module == systemLoad || module == proxySelf)
    return;
  if(IsWindowsSystemModule(module) || !MarkModuleForPatch(module))
    return;

  if(lstrcmpiA(label, "snapshot") == 0)
  {
    Trace("proxy snapshot loader-only patch\r\n");
  }
  else
  {
    LONG count = InterlockedIncrement(&runtimeModulePatchCount);
    if(count > 2)
    {
      char msg[160] = {};
      wsprintfA(msg, "proxy skip runtime module IAT patch count=%ld module=%p %s\r\n", count,
                module, label ? label : "");
      Trace(msg);
      return;
    }

    Trace("proxy runtime loader-only patch\r\n");
  }

  PatchModuleLoaderIAT(module, label);
  if(IsYuanShenProcess())
    Trace("proxy skip DXGI IAT patch for yuanshen\r\n");
  else
    PatchModuleDXGIIAT(module, label);
}

static void PatchExistingProcessModules()
{
  HANDLE snapshot =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
  if(snapshot == INVALID_HANDLE_VALUE)
  {
    TraceLastError("proxy module snapshot failed");
    return;
  }

  MODULEENTRY32W entry = {};
  entry.dwSize = sizeof(entry);

  uint32_t visited = 0;
  if(Module32FirstW(snapshot, &entry))
  {
    do
    {
      PatchLoadedModuleIATs(entry.hModule, "snapshot");
      visited++;
    } while(Module32NextW(snapshot, &entry));
  }
  else
  {
    TraceLastError("proxy module snapshot first failed");
  }

  CloseHandle(snapshot);

  char msg[128] = {};
  wsprintfA(msg, "proxy module snapshot visited=%u\r\n", visited);
  Trace(msg);
}

static void TraceLastError(const char *prefix)
{
  char msg[256] = {};
  wsprintfA(msg, "%s err=%u\r\n", prefix, GetLastError());
  Trace(msg);
}

static char *TerminateLine(char *line)
{
  char *p = line;
  while(*p && *p != '\r' && *p != '\n')
    p++;

  if(*p == '\r')
    *p++ = 0;
  if(*p == '\n')
    *p++ = 0;

  return p;
}

static bool LoadSidecarConfig()
{
  HMODULE self = NULL;
  if(!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         (LPCSTR)&LoadSidecarConfig, &self))
    return false;

  char configPath[MAX_PATH] = {};
  if(GetModuleFileNameA(self, configPath, MAX_PATH) == 0)
    return false;

  if(lstrlenA(configPath) + 10 >= MAX_PATH)
    return false;

  lstrcatA(configPath, ".sqcproxy");

  HANDLE h = CreateFileA(configPath, GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if(h == INVALID_HANDLE_VALUE)
    return false;

  char buffer[32768] = {};
  DWORD read = 0;
  BOOL ok = ReadFile(h, buffer, sizeof(buffer) - 1, &read, NULL);
  CloseHandle(h);

  if(!ok || read == 0)
    return false;

  char *systemLoad = buffer;
  char *captureFile = TerminateLine(systemLoad);
  char *captureOpts = TerminateLine(captureFile);
  char *debugLog = TerminateLine(captureOpts);
  char *identFile = TerminateLine(debugLog);
  char *flags = TerminateLine(identFile);
  TerminateLine(flags);

  if(systemLoad[0] == 0 || identFile[0] == 0)
    return false;

  SetEnvironmentVariableA("SQC_PROXY_SYSTEM_LOAD", systemLoad);
  SetEnvironmentVariableA("SQC_PROXY_CAPTURE_FILE", captureFile);
  SetEnvironmentVariableA("SQC_PROXY_CAPTURE_OPTS", captureOpts);
  SetEnvironmentVariableA("SQC_PROXY_DEBUG_LOG", debugLog);
  SetEnvironmentVariableA("SQC_PROXY_IDENT_FILE", identFile);
  SetEnvironmentVariableA("SQC_PROXY_FLAGS", flags);

  Trace("proxy loaded sidecar config\r\n");
  return true;
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

static void LoadCaptureLibrary()
{
  LONG prev = InterlockedCompareExchange(&captureLoadState, 1, 0);
  if(prev == 2)
    return;
  if(prev == 1)
  {
    while(InterlockedCompareExchange(&captureLoadState, 2, 2) != 2)
      Sleep(10);
    return;
  }

  SetEnvironmentVariableA("SQC_DISABLE_YUANSHEN_DLLMAIN_EARLY_OUT", "1");
  SetEnvironmentVariableA("SQC_DISABLE_YUANSHEN_MINIMAL_LOAD", "1");
  SetEnvironmentVariableA("SQC_DISABLE_YUANSHEN_CONTROL_ONLY", "1");

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

  InterlockedExchange(&captureLoadState, 2);
}

static FARPROC InternalD3D11Proc(const char *name)
{
  LoadCaptureLibrary();
  return systemLoad ? GetProcAddress(systemLoad, name) : NULL;
}

static void WrapCreatedD3D11Device(int DriverType, UINT Flags, const void *pFeatureLevels,
                                   UINT FeatureLevels, UINT SDKVersion, void **ppDevice,
                                   void **ppImmediateContext, void **ppSwapChain,
                                   HWND outputWindow)
{
  PFN_D3D11_WRAP_CREATED_DEVICE wrap =
      (PFN_D3D11_WRAP_CREATED_DEVICE)InternalD3D11Proc("INTERNAL_D3D11WrapCreatedDevice");
  if(wrap == NULL)
  {
    Trace("proxy missing INTERNAL_D3D11WrapCreatedDevice\r\n");
    return;
  }

  HRESULT hr = wrap(DriverType, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice,
                    ppImmediateContext, ppSwapChain, outputWindow);
  char msg[256] = {};
  wsprintfA(msg, "proxy wrap created D3D11 device hr=0x%08X device=%p ctx=%p swap=%p\r\n",
            (unsigned int)hr, ppDevice ? *ppDevice : NULL,
            ppImmediateContext ? *ppImmediateContext : NULL, ppSwapChain ? *ppSwapChain : NULL);
  Trace(msg);
}

static void EnsureLoaderFunctions()
{
  HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
  if(kernel32 == NULL)
    return;

  if(realGetProcAddress == NULL)
    realGetProcAddress = (PFN_GETPROCADDRESS)GetProcAddress(kernel32, "GetProcAddress");
  if(realLoadLibraryA == NULL)
    realLoadLibraryA = (PFN_LOADLIBRARYA)GetProcAddress(kernel32, "LoadLibraryA");
  if(realLoadLibraryW == NULL)
    realLoadLibraryW = (PFN_LOADLIBRARYW)GetProcAddress(kernel32, "LoadLibraryW");
  if(realLoadLibraryExA == NULL)
    realLoadLibraryExA = (PFN_LOADLIBRARYEXA)GetProcAddress(kernel32, "LoadLibraryExA");
  if(realLoadLibraryExW == NULL)
    realLoadLibraryExW = (PFN_LOADLIBRARYEXW)GetProcAddress(kernel32, "LoadLibraryExW");
}

static BOOL CALLBACK FindVisibleWindowForCurrentProcess(HWND wnd, LPARAM param)
{
  DWORD wndPid = 0;
  GetWindowThreadProcessId(wnd, &wndPid);
  if(wndPid != GetCurrentProcessId() || !IsWindowVisible(wnd))
    return TRUE;

  *((HWND *)param) = wnd;
  return FALSE;
}

static DWORD WINAPI DeferredCaptureThread(void *)
{
  Trace("proxy deferred capture thread begin\r\n");

  for(uint32_t i = 0; i < 600; i++)
  {
    HWND wnd = NULL;
    EnumWindows(FindVisibleWindowForCurrentProcess, (LPARAM)&wnd);
    if(wnd != NULL)
    {
      Trace("proxy deferred visible window detected\r\n");
      break;
    }

    Sleep(100);
  }

  LoadCaptureLibrary();
  Trace("proxy deferred capture thread end\r\n");
  return 0;
}

static void Init()
{
  char msg[128] = {};
  wsprintfA(msg, "proxy init pid=%u\r\n", GetCurrentProcessId());
  Trace(msg);

  LONG prev = InterlockedCompareExchange(&initState, 1, 0);
  if(prev == 2)
    return;
  if(prev == 1)
  {
    while(InterlockedCompareExchange(&initState, 2, 2) != 2)
      Sleep(1);
    return;
  }

  LoadSidecarConfig();

  if(BootstrapOnly())
  {
    Trace("proxy bootstrap-only mode\r\n");
    WriteIdent(38920);
    InterlockedExchange(&initState, 2);
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

  wchar_t dxgiPath[MAX_PATH] = {};
  GetSystemDirectoryW(dxgiPath, MAX_PATH);
  lstrcatW(dxgiPath, L"\\dxgi.dll");
  realDXGI = LoadLibraryW(dxgiPath);
  if(realDXGI)
    Trace("proxy loaded real dxgi\r\n");
  else
    TraceLastError("proxy failed to load real dxgi");

  EnsureLoaderFunctions();

  if(DeferredCapture())
  {
    PatchMainModuleD3D11IAT();
    PatchMainModuleLoaderIAT();
    PatchExistingProcessModules();
  }

  if(DeferredCapture())
  {
    Trace("proxy deferred capture mode\r\n");
    HANDLE thread = CreateThread(NULL, 0, DeferredCaptureThread, NULL, 0, NULL);
    if(thread)
      CloseHandle(thread);
    else
      TraceLastError("proxy failed to create deferred capture thread");
  }
  else
  {
    LoadCaptureLibrary();
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

static FARPROC RealDXGIProc(const char *name)
{
  Init();
  return realDXGI ? GetProcAddress(realDXGI, name) : NULL;
}

static void WrapDXGIFactory(REFIID riid, void **ppFactory)
{
  if(ppFactory == NULL || *ppFactory == NULL)
    return;

  if(IsYuanShenProcess())
  {
    Trace("proxy skip wrapping DXGI factory for yuanshen\r\n");
    return;
  }

  PFN_DXGI_WRAP_FACTORY wrap =
      (PFN_DXGI_WRAP_FACTORY)InternalD3D11Proc("INTERNAL_DXGIWrapFactory");
  if(wrap == NULL)
  {
    Trace("proxy missing INTERNAL_DXGIWrapFactory\r\n");
    return;
  }

  HRESULT hr = wrap(riid, ppFactory);
  char msg[192] = {};
  wsprintfA(msg, "proxy wrap DXGI factory hr=0x%08X factory=%p\r\n", (unsigned int)hr,
            ppFactory ? *ppFactory : NULL);
  Trace(msg);
}

static void HookFactorySwapchainCreates(void **ppFactory)
{
  if(ppFactory == NULL || *ppFactory == NULL || !IsYuanShenProcess())
    return;

  if(InterlockedCompareExchange(&d3d11ShadowReady, 0, 0) == 0)
  {
    Trace("proxy defer factory swapchain hook until D3D11 shadow ready\r\n");
    return;
  }

  PFN_DXGI_HOOK_FACTORY_SWAPCHAIN_CREATES hook =
      (PFN_DXGI_HOOK_FACTORY_SWAPCHAIN_CREATES)InternalD3D11Proc(
          "INTERNAL_DXGIHookFactorySwapchainCreates");
  if(hook == NULL)
  {
    Trace("proxy missing INTERNAL_DXGIHookFactorySwapchainCreates\r\n");
    return;
  }

  HRESULT hr = hook((IUnknown *)*ppFactory);
  char msg[192] = {};
  wsprintfA(msg, "proxy hook factory swapchain creates hr=0x%08X factory=%p\r\n",
            (unsigned int)hr, *ppFactory);
  Trace(msg);
}

extern "C" FARPROC WINAPI Proxy_GetProcAddress(HMODULE module, LPCSTR name)
{
  EnsureLoaderFunctions();

  if(((uintptr_t)name >> 16) != 0 && IsD3D11CreateName(name) && IsD3D11Module(module))
  {
    char msg[160] = {};
    wsprintfA(msg, "proxy loader GetProcAddress %s module=%p\r\n", name, module);
    Trace(msg);

    if(lstrcmpiA(name, "D3D11CreateDevice") == 0)
      return (FARPROC)&Proxy_D3D11CreateDevice;

    return (FARPROC)&Proxy_D3D11CreateDeviceAndSwapChain;
  }

  if(((uintptr_t)name >> 16) != 0 && IsDXGIFactoryName(name) && IsDXGIModule(module))
  {
    if(IsYuanShenProcess())
    {
      char msg[192] = {};
      if(!EnvEnabled("SQC_ENABLE_YUANSHEN_THIN_DXGI_HOOK") &&
         !EnvEnabled("SQC_ENABLE_YUANSHEN_LATE_DXGI_HOOK"))
      {
        wsprintfA(msg, "proxy skip thin DXGI GetProcAddress %s for yuanshen module=%p\r\n",
                  name, module);
        Trace(msg);
        return realGetProcAddress ? realGetProcAddress(module, name) : NULL;
      }

      if(!EnvEnabled("SQC_ENABLE_YUANSHEN_THIN_DXGI_HOOK") &&
         InterlockedCompareExchange(&d3d11ShadowReady, 0, 0) == 0)
      {
        wsprintfA(msg, "proxy skip late DXGI GetProcAddress %s before D3D11 shadow ready "
                       "for yuanshen module=%p\r\n",
                  name, module);
        Trace(msg);
        return realGetProcAddress ? realGetProcAddress(module, name) : NULL;
      }

      wsprintfA(msg, "proxy late DXGI GetProcAddress %s for yuanshen module=%p ready=%ld\r\n",
                name, module, InterlockedCompareExchange(&d3d11ShadowReady, 0, 0));
      Trace(msg);

      if(lstrcmpiA(name, "CreateDXGIFactory") == 0)
        return (FARPROC)&Proxy_CreateDXGIFactory;
      if(lstrcmpiA(name, "CreateDXGIFactory1") == 0)
        return (FARPROC)&Proxy_CreateDXGIFactory1;
      return (FARPROC)&Proxy_CreateDXGIFactory2;
    }

    char msg[160] = {};
    wsprintfA(msg, "proxy loader GetProcAddress %s module=%p\r\n", name, module);
    Trace(msg);

    if(lstrcmpiA(name, "CreateDXGIFactory") == 0)
      return (FARPROC)&Proxy_CreateDXGIFactory;
    if(lstrcmpiA(name, "CreateDXGIFactory1") == 0)
      return (FARPROC)&Proxy_CreateDXGIFactory1;
    return (FARPROC)&Proxy_CreateDXGIFactory2;
  }

  return realGetProcAddress ? realGetProcAddress(module, name) : NULL;
}

extern "C" HMODULE WINAPI Proxy_LoadLibraryA(LPCSTR name)
{
  EnsureLoaderFunctions();

  HMODULE module = realLoadLibraryA ? realLoadLibraryA(name) : NULL;
  PatchLoadedModuleIATs(module, "LoadLibraryA");
  if(IsD3D11PathA(name))
  {
    char msg[160] = {};
    wsprintfA(msg, "proxy loader LoadLibraryA d3d11 module=%p\r\n", module);
    Trace(msg);
  }
  else if(IsDXGIPathA(name))
  {
    char msg[160] = {};
    wsprintfA(msg, "proxy loader LoadLibraryA dxgi module=%p\r\n", module);
    Trace(msg);
  }

  return module;
}

extern "C" HMODULE WINAPI Proxy_LoadLibraryW(LPCWSTR name)
{
  EnsureLoaderFunctions();

  HMODULE module = realLoadLibraryW ? realLoadLibraryW(name) : NULL;
  PatchLoadedModuleIATs(module, "LoadLibraryW");
  if(IsD3D11PathW(name))
  {
    char msg[160] = {};
    wsprintfA(msg, "proxy loader LoadLibraryW d3d11 module=%p\r\n", module);
    Trace(msg);
  }
  else if(IsDXGIPathW(name))
  {
    char msg[160] = {};
    wsprintfA(msg, "proxy loader LoadLibraryW dxgi module=%p\r\n", module);
    Trace(msg);
  }

  return module;
}

extern "C" HMODULE WINAPI Proxy_LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags)
{
  EnsureLoaderFunctions();

  HMODULE module = realLoadLibraryExA ? realLoadLibraryExA(name, file, flags) : NULL;
  PatchLoadedModuleIATs(module, "LoadLibraryExA");
  if(IsD3D11PathA(name))
  {
    char msg[192] = {};
    wsprintfA(msg, "proxy loader LoadLibraryExA d3d11 module=%p flags=0x%08X\r\n", module,
              (unsigned int)flags);
    Trace(msg);
  }
  else if(IsDXGIPathA(name))
  {
    char msg[192] = {};
    wsprintfA(msg, "proxy loader LoadLibraryExA dxgi module=%p flags=0x%08X\r\n", module,
              (unsigned int)flags);
    Trace(msg);
  }

  return module;
}

extern "C" HMODULE WINAPI Proxy_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
  EnsureLoaderFunctions();

  HMODULE module = realLoadLibraryExW ? realLoadLibraryExW(name, file, flags) : NULL;
  PatchLoadedModuleIATs(module, "LoadLibraryExW");
  if(IsD3D11PathW(name))
  {
    char msg[192] = {};
    wsprintfA(msg, "proxy loader LoadLibraryExW d3d11 module=%p flags=0x%08X\r\n", module,
              (unsigned int)flags);
    Trace(msg);
  }
  else if(IsDXGIPathW(name))
  {
    char msg[192] = {};
    wsprintfA(msg, "proxy loader LoadLibraryExW dxgi module=%p flags=0x%08X\r\n", module,
              (unsigned int)flags);
    Trace(msg);
  }

  return module;
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

extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory(REFIID riid, void **ppFactory)
{
  PFN_CREATE_DXGI_FACTORY fn = (PFN_CREATE_DXGI_FACTORY)RealDXGIProc("CreateDXGIFactory");
  HRESULT hr = fn ? fn(riid, ppFactory) : E_FAIL;
  char msg[192] = {};
  wsprintfA(msg, "proxy CreateDXGIFactory hr=0x%08X factory=%p\r\n", (unsigned int)hr,
            ppFactory ? *ppFactory : NULL);
  Trace(msg);

  if(SUCCEEDED(hr))
  {
    HookFactorySwapchainCreates(ppFactory);
    WrapDXGIFactory(riid, ppFactory);
  }

  return hr;
}

extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory1(REFIID riid, void **ppFactory)
{
  PFN_CREATE_DXGI_FACTORY fn = (PFN_CREATE_DXGI_FACTORY)RealDXGIProc("CreateDXGIFactory1");
  HRESULT hr = fn ? fn(riid, ppFactory) : E_FAIL;
  char msg[192] = {};
  wsprintfA(msg, "proxy CreateDXGIFactory1 hr=0x%08X factory=%p\r\n", (unsigned int)hr,
            ppFactory ? *ppFactory : NULL);
  Trace(msg);

  if(SUCCEEDED(hr))
  {
    HookFactorySwapchainCreates(ppFactory);
    WrapDXGIFactory(riid, ppFactory);
  }

  return hr;
}

extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory2(UINT Flags, REFIID riid, void **ppFactory)
{
  PFN_CREATE_DXGI_FACTORY2 fn =
      (PFN_CREATE_DXGI_FACTORY2)RealDXGIProc("CreateDXGIFactory2");
  HRESULT hr = fn ? fn(Flags, riid, ppFactory) : E_FAIL;
  char msg[224] = {};
  wsprintfA(msg, "proxy CreateDXGIFactory2 flags=0x%X hr=0x%08X factory=%p\r\n", Flags,
            (unsigned int)hr, ppFactory ? *ppFactory : NULL);
  Trace(msg);

  if(SUCCEEDED(hr))
  {
    HookFactorySwapchainCreates(ppFactory);
    WrapDXGIFactory(riid, ppFactory);
  }

  return hr;
}

extern "C" HRESULT WINAPI Proxy_D3D11CreateDevice(
    void *pAdapter, int DriverType, HMODULE Software, UINT Flags, const void *pFeatureLevels,
    UINT FeatureLevels, UINT SDKVersion, void **ppDevice, void *pFeatureLevel,
    void **ppImmediateContext)
{
  PFN_D3D11_CREATE_DEVICE fn = (PFN_D3D11_CREATE_DEVICE)RealProc("D3D11CreateDevice");
  HRESULT hr = fn ? fn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                       SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext)
                  : E_FAIL;
  char msg[256] = {};
  wsprintfA(msg, "proxy D3D11CreateDevice hr=0x%08X device=%p ctx=%p\r\n", (unsigned int)hr,
            ppDevice ? *ppDevice : NULL, ppImmediateContext ? *ppImmediateContext : NULL);
  Trace(msg);

  if(SUCCEEDED(hr) && ppDevice != NULL && *ppDevice != NULL)
  {
    WrapCreatedD3D11Device(DriverType, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice,
                           ppImmediateContext, NULL, NULL);
    InterlockedExchange(&d3d11ShadowReady, 1);
    Trace("proxy D3D11 shadow ready\r\n");
  }

  return hr;
}

extern "C" HRESULT WINAPI Proxy_D3D11CreateDeviceAndSwapChain(
    void *pAdapter, int DriverType, HMODULE Software, UINT Flags, const void *pFeatureLevels,
    UINT FeatureLevels, UINT SDKVersion, const void *pSwapChainDesc, void **ppSwapChain,
    void **ppDevice, void *pFeatureLevel, void **ppImmediateContext)
{
  PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN fn =
      (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)RealProc("D3D11CreateDeviceAndSwapChain");
  HRESULT hr = fn ? fn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                       SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel,
                       ppImmediateContext)
                  : E_FAIL;
  char msg[256] = {};
  wsprintfA(msg, "proxy D3D11CreateDeviceAndSwapChain hr=0x%08X device=%p swap=%p ctx=%p\r\n",
            (unsigned int)hr, ppDevice ? *ppDevice : NULL, ppSwapChain ? *ppSwapChain : NULL,
            ppImmediateContext ? *ppImmediateContext : NULL);
  Trace(msg);

  if(SUCCEEDED(hr) && ppDevice != NULL && *ppDevice != NULL)
  {
    WrapCreatedD3D11Device(DriverType, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice,
                           ppImmediateContext, ppSwapChain, NULL);
    InterlockedExchange(&d3d11ShadowReady, 1);
    Trace("proxy D3D11 shadow ready\r\n");
  }

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
    proxySelf = hinst;
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
