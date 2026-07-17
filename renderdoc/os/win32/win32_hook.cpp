/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2025 Baldur Karlsson
 * Copyright (c) 2014 Crytek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

// must be separate so that it's included first and not sorted by clang-format
#include <windows.h>

#include <tlhelp32.h>
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include "3rdparty/minhook/include/MinHook.h"
#include "common/common.h"
#include "common/threading.h"
#include "hooks/hooks.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"

#define VERBOSE_DEBUG_HOOK OPTION_OFF

// map from address of IAT entry, to original contents
std::map<void **, void *> s_InstalledHooks;
Threading::CriticalSection installedLock;
static thread_local int s_SuppressHooking = 0;

static void SQCChainLog(const char *msg)
{
  static const bool enabled = []() {
    char value[16] = {};
    DWORD len = GetEnvironmentVariableA("SQC_DIAG_HOOK_CHAIN", value, sizeof(value));
    return len > 0 && _stricmp(value, "0") != 0 && _stricmp(value, "false") != 0 &&
           _stricmp(value, "off") != 0;
  }();

  if(!enabled)
    return;

  char path[MAX_PATH] = {};
  GetTempPathA(MAX_PATH, path);
  strcat_s(path, MAX_PATH, "sqc_hook_chain.txt");

  HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(h == INVALID_HANDLE_VALUE)
    return;

  char buf[512] = {};
  DWORD written = 0;
  wsprintfA(buf, "[SQC-CHAIN] tick=%u pid=%u %s\r\n", GetTickCount(), GetCurrentProcessId(), msg);
  WriteFile(h, buf, lstrlenA(buf), &written, NULL);
  CloseHandle(h);
}

static bool SQCEnvEnabled(const char *name);
static bool IsLoaderHookLibrary(const char *dllName);

static bool ShouldSkipFunctionHook(const char *modName, const char *dllName, const char *function,
                                   HMODULE module)
{
  if(modName == NULL || dllName == NULL || function == NULL)
    return false;

  rdcstr lowerModName = strlower(rdcstr(modName));
  if(strstr(lowerModName.c_str(), "gameoverlayrenderer") != NULL)
  {
    char msg[512] = {};
    wsprintfA(msg, "ApplyHooks skip overlay function module=%s import=%s function=%s", modName,
              dllName, function);
    SQCChainLog(msg);
    return true;
  }

  if(SQCEnvEnabled("SQC_D3D11_LIGHT_HOOKS") && IsLoaderHookLibrary(dllName))
  {
    // Keep one GetProcAddress hook in the executable as a fallback for dynamically resolved
    // D3D11/DXGI exports. Hooking LoadLibrary or every DLL's GetProcAddress sends unrelated loader
    // traffic through our hook; that matches the observed pre-D3D11 ntdll startup faults. Limiting
    // the fallback to the executable preserves the capture entry without modifying the rest of the
    // loader path.
    if(_stricmp(function, "GetProcAddress") != 0)
      return true;

    return module != GetModuleHandleW(NULL);
  }

  return false;
}

static bool IsLoaderHookLibrary(const char *dllName)
{
  if(dllName == NULL)
    return false;

  return !_stricmp(dllName, "kernel32.dll") ||
         _strnicmp(dllName, "api-ms-win-core-libraryloader-", 30) == 0;
}

static void *FetchOriginalFunction(HMODULE module, const FunctionHook &hook)
{
  ScopedSuppressHooking suppress;
  FARPROC proc = GetProcAddress(module, hook.function.c_str());

  if(proc != NULL && proc == (FARPROC)hook.hook)
  {
    char msg[512] = {};
    wsprintfA(msg, "FetchOriginalFunction self-hook libraryModule=%p function=%s hook=%p", module,
              hook.function.c_str(), hook.hook);
    SQCChainLog(msg);
    return NULL;
  }

  return (void *)proc;
}

static bool IsDXGIFactoryFunction(const char *func)
{
  return func && (!_stricmp(func, "CreateDXGIFactory") ||
                  !_stricmp(func, "CreateDXGIFactory1") ||
                  !_stricmp(func, "CreateDXGIFactory2"));
}

static bool SQCEnvEnabled(const char *name)
{
  char value[16] = {};
  DWORD len = GetEnvironmentVariableA(name, value, sizeof(value));
  return len > 0 && _stricmp(value, "0") != 0 && _stricmp(value, "false") != 0 &&
         _stricmp(value, "off") != 0;
}

static bool SQCAllowLightHookLibrary(const char *libraryName)
{
  if(!SQCEnvEnabled("SQC_D3D11_LIGHT_HOOKS"))
    return true;

  if(libraryName == NULL)
    return false;

  return !_stricmp(libraryName, "d3d11.dll") || !_stricmp(libraryName, "dxgi.dll");
}

static bool SQCIsLightHookSystemModule(const wchar_t *lowerModPath)
{
  if(!SQCEnvEnabled("SQC_D3D11_LIGHT_HOOKS"))
    return false;

  if(lowerModPath == NULL || lowerModPath[0] == 0)
    return false;

  return wcsstr(lowerModPath, L"\\windows\\system32\\") != NULL ||
         wcsstr(lowerModPath, L"\\windows\\syswow64\\") != NULL ||
         wcsstr(lowerModPath, L"\\windows\\winsxs\\") != NULL;
}

static volatile LONG SQC_CaptureEntryHookCount = 0;

static bool SQCIsCaptureEntryHook(const char *dllName, const char *function)
{
  return !_stricmp(dllName, "d3d11.dll") || !_stricmp(dllName, "dxgi.dll") ||
         !_stricmp(function, "GetProcAddress");
}

bool ApplyHook(FunctionHook &hook, void **IATentry, bool &already, const char *modName,
               const char *dllName, HMODULE module)
{
  DWORD oldProtection = PAGE_EXECUTE;

  if(ShouldSkipFunctionHook(modName, dllName, hook.function.c_str(), module))
    return true;

  if(*IATentry == hook.hook)
  {
    already = true;
    if(SQCIsCaptureEntryHook(dllName, hook.function.c_str()))
      InterlockedIncrement(&SQC_CaptureEntryHookCount);
    return true;
  }

  if(hook.function == "D3D11CreateDevice" ||
     hook.function == "D3D11CreateDeviceAndSwapChain" ||
     hook.function == "CreateDXGIFactory" || hook.function == "CreateDXGIFactory1" ||
     hook.function == "CreateDXGIFactory2" || hook.function == "GetProcAddress")
  {
    char msg[512] = {};
    wsprintfA(msg, "ApplyHook module=%s import=%s function=%s iat=%p hook=%p",
              modName ? modName : "<null>", dllName ? dllName : "<null>", hook.function.c_str(),
              IATentry, hook.hook);
    SQCChainLog(msg);
  }

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("Patching IAT for %s: %p to %p", hook.function.c_str(), IATentry, hook.hook);
#endif

  {
    SCOPED_LOCK(installedLock);
    if(s_InstalledHooks.find(IATentry) == s_InstalledHooks.end())
      s_InstalledHooks[IATentry] = *IATentry;
  }

  BOOL success = VirtualProtect(IATentry, sizeof(void *), PAGE_READWRITE, &oldProtection);
  if(!success)
  {
    RDCERR("Failed to make IAT entry writeable 0x%p", IATentry);
    return false;
  }

  *IATentry = hook.hook;

  success = VirtualProtect(IATentry, sizeof(void *), oldProtection, &oldProtection);
  if(!success)
  {
    RDCERR("Failed to restore IAT entry protection 0x%p", IATentry);
    return false;
  }

  if(SQCIsCaptureEntryHook(dllName, hook.function.c_str()))
    InterlockedIncrement(&SQC_CaptureEntryHookCount);

  return true;
}

struct DllHookset
{
  HMODULE module = NULL;
  bool hooksfetched = false;
  // if we have multiple copies of the dll loaded (unlikely), the other module handles will be
  // stored here
  rdcarray<HMODULE> altmodules;
  rdcarray<FunctionHook> FunctionHooks;
  DWORD OrdinalBase = 0;
  rdcarray<rdcstr> OrdinalNames;
  rdcarray<FunctionLoadCallback> Callbacks;
  Threading::CriticalSection ordinallock;

  void FetchOrdinalNames()
  {
    SCOPED_LOCK(ordinallock);

    // return if we already fetched the ordinals
    if(!OrdinalNames.empty())
      return;

    byte *baseAddress = (byte *)module;

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("FetchOrdinalNames");
#endif

    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)baseAddress;

    if(dosheader->e_magic != 0x5a4d)
      return;

    char *PE00 = (char *)(baseAddress + dosheader->e_lfanew);
    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(PE00 + 4);
    PIMAGE_OPTIONAL_HEADER optHeader =
        (PIMAGE_OPTIONAL_HEADER)((BYTE *)fileHeader + sizeof(IMAGE_FILE_HEADER));

    DWORD eatOffset = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    IMAGE_EXPORT_DIRECTORY *exportDesc = (IMAGE_EXPORT_DIRECTORY *)(baseAddress + eatOffset);

    WORD *ordinals = (WORD *)(baseAddress + exportDesc->AddressOfNameOrdinals);
    DWORD *names = (DWORD *)(baseAddress + exportDesc->AddressOfNames);

    DWORD count = RDCMIN(exportDesc->NumberOfFunctions, exportDesc->NumberOfNames);

    WORD maxOrdinal = 0;
    for(DWORD i = 0; i < count; i++)
      maxOrdinal = RDCMAX(maxOrdinal, ordinals[i]);

    OrdinalBase = exportDesc->Base;
    OrdinalNames.resize(maxOrdinal + 1);

    for(DWORD i = 0; i < count; i++)
    {
      OrdinalNames[ordinals[i]] = (char *)(baseAddress + names[i]);

#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("ordinal found: '%s' %u", OrdinalNames[ordinals[i]].c_str(), (uint32_t)ordinals[i]);
#endif
    }
  }
};

struct CachedHookData
{
  bool hookAll = true;

  std::map<rdcstr, DllHookset> DllHooks;
  HMODULE ownmodule = NULL;
  Threading::CriticalSection lock;

  std::set<rdcstr> ignores;

  bool missedOrdinals = false;
  std::function<HMODULE(const rdcstr &, HANDLE, DWORD)> libraryIntercept;

  int32_t posthooking = 0;

  void ApplyHooks(const char *modName, HMODULE module)
  {
    char lowername[512] = {};
    {
      size_t i = 0;
      while(modName[i] && i < sizeof(lowername) - 1)
      {
        lowername[i] = (char)tolower(modName[i]);
        i++;
      }
      lowername[i] = 0;
    }

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("=== ApplyHooks(%s, %p)", modName, module);
#endif

    // fraps seems to non-safely modify the assembly around the hook function, if
    // we modify its import descriptors it leads to a crash as it hooks OUR functions.
    // instead, skip modifying the import descriptors, it will hook the 'real' d3d functions
    // and we can call them and have fraps + renderdoc playing nicely together.
    // we also exclude some other overlay renderers here, such as steam's
    //
    // Also exclude ourselves. This fork's capture DLL is renamed, so matching only
    // RDOC_BASE_NAME.dll is not enough.
    if(module == ownmodule)
    {
      char msg[512] = {};
      wsprintfA(msg, "ApplyHooks skip own module=%s module=%p", modName, module);
      SQCChainLog(msg);
      return;
    }

    if(strstr(lowername, "fraps") || strstr(lowername, "gameoverlayrenderer") ||
       strstr(lowername, STRINGIZE(RDOC_BASE_NAME) ".dll") == lowername ||
       strstr(lowername, "system_load.dll") || strstr(lowername, "d3d11_proxy.dll"))
    {
      char msg[512] = {};
      wsprintfA(msg, "ApplyHooks skip overlay/self module=%s module=%p", modName, module);
      SQCChainLog(msg);
      return;
    }

    // set module pointer if we are hooking exports from this module
    for(auto it = DllHooks.begin(); it != DllHooks.end(); ++it)
    {
      if(!_stricmp(it->first.c_str(), modName))
      {
        if(it->second.module == NULL)
        {
          it->second.module = module;

          it->second.hooksfetched = true;

          // fetch all function hooks here, since we want to fill out the original function pointer
          // even in case nothing imports from that function (which means it would not get filled
          // out through FunctionHook::ApplyHook)
          for(FunctionHook &hook : it->second.FunctionHooks)
          {
            if(hook.orig && *hook.orig == NULL)
              *hook.orig = FetchOriginalFunction(module, hook);
          }

          it->second.FetchOrdinalNames();
        }
        else if(it->second.module != module)
        {
          // if it's already in altmodules, bail
          bool already = false;

          for(size_t i = 0; i < it->second.altmodules.size(); i++)
          {
            if(it->second.altmodules[i] == module)
            {
              already = true;
              break;
            }
          }

          if(already)
            break;

          // check if the previous module is still valid
          SetLastError(0);
          char filename[MAX_PATH] = {};
          GetModuleFileNameA(it->second.module, filename, MAX_PATH - 1);
          DWORD err = GetLastError();
          char *slash = strrchr(filename, L'\\');

          rdcstr basename = slash ? strlower(rdcstr(slash + 1)) : "";

          if(err == 0 && basename == it->first)
          {
            // previous module is still loaded, add this to the alt modules list
            it->second.altmodules.push_back(module);
          }
          else
          {
            // previous module is no longer loaded or there's a new file there now, add this as the
            // new location
            RDCWARN("%s moved from %p to %p, re-initialising orig pointers", it->first.c_str(),
                    it->second.module, module);

            // we also need to re-initialise the hooks as the orig pointers are now stale
            for(FunctionHook &hook : it->second.FunctionHooks)
            {
              if(hook.orig)
                *hook.orig = FetchOriginalFunction(module, hook);
            }

            it->second.module = module;
          }
        }
      }
    }

    // for safety (and because we don't need to), ignore these modules
    if(!_stricmp(modName, "kernel32.dll") || !_stricmp(modName, "powrprof.dll") ||
       !_stricmp(modName, "CoreMessaging.dll") || !_stricmp(modName, "opengl32.dll") ||
       !_stricmp(modName, "gdi32.dll") || !_stricmp(modName, "gdi32full.dll") ||
       !_stricmp(modName, "windows.storage.dll") || !_stricmp(modName, "nvoglv32.dll") ||
       !_stricmp(modName, "nvoglv64.dll") || !_stricmp(modName, "vulkan-1.dll") ||
       !_stricmp(modName, "atio6axx.dll") || !_stricmp(modName, "atioglxx.dll") ||
       !_stricmp(modName, "nvcuda.dll") || strstr(lowername, "cudart") == lowername ||
       strstr(lowername, "msvcr") == lowername || strstr(lowername, "msvcp") == lowername ||
       strstr(lowername, "nv-vk") == lowername || strstr(lowername, "amdvlk") == lowername ||
       strstr(lowername, "igvk") == lowername || strstr(lowername, "nvopencl") == lowername ||
       strstr(lowername, "nvapi") == lowername)
      return;

    if(ignores.find(lowername) != ignores.end())
      return;

    // the module could have been unloaded after our toolhelp snapshot, especially if we spent a
    // long time
    // dealing with a previous module (like adding our hooks).
    wchar_t modpath[1024] = {0};
    GetModuleFileNameW(module, modpath, 1023);
    if(modpath[0] == 0)
      return;

    bool isWindowsSystemModule = false;
    wchar_t lowerModPath[1024] = {};
    {
      size_t i = 0;
      while(modpath[i])
      {
        lowerModPath[i] = towlower(modpath[i]);
        i++;
      }
      lowerModPath[i] = 0;

      isWindowsSystemModule = wcsstr(lowerModPath, L"\\windows\\system32\\") != NULL ||
                              wcsstr(lowerModPath, L"\\windows\\syswow64\\") != NULL;
    }

    if(SQCIsLightHookSystemModule(lowerModPath))
    {
      if(!_stricmp(modName, "d3d11.dll") || !_stricmp(modName, "dxgi.dll"))
      {
        char msg[256] = {};
        wsprintfA(msg, "ApplyHooks light skip system hook library module=%s", modName);
        SQCChainLog(msg);
      }
      return;
    }

    // windows 11 and newer versions have weird hotpatch DLLs that don't act like real DLLs. The
    // LoadLibraryW below will fail for these DLLs even when using the module path provided.
    // Only check the path for DLLs that might be a windows-hotpatch but if it matches we'll skip
    // hooking these to avoid problems
    if(strstr(lowername, "hotpatch"))
    {
      if(wcsstr(lowerModPath, L"\\windows\\winsxs\\"))
        return;
    }

    // increment the module reference count, so it doesn't disappear while we're processing it
    // there's a very small race condition here between if GetModuleFileName returns, the module is
    // unloaded then we load it again. The only way around that is inserting very scary locks
    // between here
    // and FreeLibrary that I want to avoid. Worst case, we load a dll, hook it, then unload it
    // again.
    HMODULE refcountModHandle = LoadLibraryW(modpath);
    RDCASSERTEQUAL(refcountModHandle, module);
    byte *baseAddress = (byte *)refcountModHandle;

    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)baseAddress;

    if(dosheader->e_magic != 0x5a4d)
    {
      RDCDEBUG("Ignoring module %s, since magic is 0x%04x not 0x%04x", modName,
               (uint32_t)dosheader->e_magic, 0x5a4dU);
      FreeLibrary(refcountModHandle);
      return;
    }

    char *PE00 = (char *)(baseAddress + dosheader->e_lfanew);
    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(PE00 + 4);
    PIMAGE_OPTIONAL_HEADER optHeader =
        (PIMAGE_OPTIONAL_HEADER)((BYTE *)fileHeader + sizeof(IMAGE_FILE_HEADER));

    DWORD iatOffset = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR *)(baseAddress + iatOffset);

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("=== import descriptors:");
#endif

    while(iatOffset && importDesc->FirstThunk)
    {
      const char *dllName = (const char *)(baseAddress + importDesc->Name);

#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("found IAT for %s", dllName);
#endif

      DllHookset *hookset = NULL;

      for(auto it = DllHooks.begin(); it != DllHooks.end(); ++it)
        if(!_stricmp(it->first.c_str(), dllName))
          hookset = &it->second;

      if(hookset && !_stricmp(modName, dllName))
      {
        if(!_stricmp(dllName, "d3d11.dll") || !_stricmp(dllName, "dxgi.dll"))
        {
          char msg[256] = {};
          wsprintfA(msg, "ApplyHooks skip self import module=%s import=%s", modName, dllName);
          SQCChainLog(msg);
        }

        hookset = NULL;
      }

      if(hookset && isWindowsSystemModule && IsLoaderHookLibrary(dllName))
      {
        char msg[256] = {};
        wsprintfA(msg, "ApplyHooks skip system loader module=%s import=%s", modName, dllName);
        SQCChainLog(msg);
        hookset = NULL;
      }

      if(hookset && isWindowsSystemModule &&
         (!_stricmp(dllName, "d3d11.dll") || !_stricmp(dllName, "dxgi.dll")))
      {
        char msg[256] = {};
        wsprintfA(msg, "ApplyHooks skip system module=%s import=%s", modName, dllName);
        SQCChainLog(msg);
        hookset = NULL;
      }

      if(hookset && importDesc->OriginalFirstThunk > 0)
      {
        IMAGE_THUNK_DATA *origFirst =
            (IMAGE_THUNK_DATA *)(baseAddress + importDesc->OriginalFirstThunk);
        IMAGE_THUNK_DATA *first = (IMAGE_THUNK_DATA *)(baseAddress + importDesc->FirstThunk);

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Hooking imports for %s", dllName);
#endif

        while(origFirst->u1.AddressOfData)
        {
          void **IATentry = (void **)&first->u1.AddressOfData;

          struct hook_find
          {
            bool operator()(const FunctionHook &a, const char *b)
            {
              return strcmp(a.function.c_str(), b) < 0;
            }
          };

#if ENABLED(RDOC_X64)
          if(IMAGE_SNAP_BY_ORDINAL64(origFirst->u1.AddressOfData))
#else
          if(IMAGE_SNAP_BY_ORDINAL32(origFirst->u1.AddressOfData))
#endif
          {
            // low bits of origFirst->u1.AddressOfData contain an ordinal
            WORD ordinal = IMAGE_ORDINAL64(origFirst->u1.AddressOfData);

#if ENABLED(VERBOSE_DEBUG_HOOK)
            RDCDEBUG("Found ordinal import %u", (uint32_t)ordinal);
#endif

            if(!hookset->OrdinalNames.empty())
            {
              if(ordinal >= hookset->OrdinalBase)
              {
                // rebase into OrdinalNames index
                DWORD nameIndex = ordinal - hookset->OrdinalBase;

                // it's perfectly valid to have more functions than names, we only
                // list those with names - so ignore any others
                if(nameIndex < hookset->OrdinalNames.size())
                {
                  const char *importName = (const char *)hookset->OrdinalNames[nameIndex].c_str();

#if ENABLED(VERBOSE_DEBUG_HOOK)
                  RDCDEBUG("Located ordinal %u as %s", (uint32_t)ordinal, importName);
#endif

                  auto found =
                      std::lower_bound(hookset->FunctionHooks.begin(), hookset->FunctionHooks.end(),
                                       importName, hook_find());

                  if(found != hookset->FunctionHooks.end() &&
                     !strcmp(found->function.c_str(), importName) && ownmodule != module)
                  {
                    if(ShouldSkipFunctionHook(modName, dllName, found->function.c_str(), module))
                    {
                      origFirst++;
                      first++;
                      continue;
                    }

                    bool already = false;
                    bool applied;
                    {
                      SCOPED_LOCK(lock);
                      applied = ApplyHook(*found, IATentry, already, modName, dllName, module);
                    }

                    // if we failed, or if it's already set and we're not doing a missedOrdinals
                    // second pass, then just bail out immediately as we've already hooked this
                    // module and there's no point wasting time re-hooking nothing
                    if(!applied || (already && !missedOrdinals))
                    {
#if ENABLED(VERBOSE_DEBUG_HOOK)
                      RDCDEBUG("Stopping hooking module, %d %d %d", (int)applied, (int)already,
                               (int)missedOrdinals);
#endif
                      FreeLibrary(refcountModHandle);
                      return;
                    }
                  }
                }
              }
              else
              {
                RDCERR("Import ordinal is below ordinal base in %s importing module %s", modName,
                       dllName);
              }
            }
            else
            {
#if ENABLED(VERBOSE_DEBUG_HOOK)
              RDCDEBUG("missed ordinals, will try again");
#endif
              // the very first time we try to apply hooks, we might apply them to a module
              // before we've looked up the ordinal names for the one it's linking against.
              // Subsequent times we're only loading one new module - and since it can't
              // link to itself we will have all ordinal names loaded.
              //
              // Setting this flag causes us to do a second pass right at the start
              missedOrdinals = true;
            }

            // continue
            origFirst++;
            first++;
            continue;
          }

          IMAGE_IMPORT_BY_NAME *import =
              (IMAGE_IMPORT_BY_NAME *)(baseAddress + origFirst->u1.AddressOfData);

          const char *importName = (const char *)import->Name;

#if ENABLED(VERBOSE_DEBUG_HOOK)
          RDCDEBUG("Found normal import %s", importName);
#endif

          auto found = std::lower_bound(hookset->FunctionHooks.begin(),
                                        hookset->FunctionHooks.end(), importName, hook_find());

          if(found != hookset->FunctionHooks.end() &&
             !strcmp(found->function.c_str(), importName) && ownmodule != module)
          {
            if(ShouldSkipFunctionHook(modName, dllName, found->function.c_str(), module))
            {
              origFirst++;
              first++;
              continue;
            }

            bool already = false;
            bool applied;
            {
                SCOPED_LOCK(lock);
                applied = ApplyHook(*found, IATentry, already, modName, dllName, module);
              }

            // if we failed, or if it's already set and we're not doing a missedOrdinals
            // second pass, then just bail out immediately as we've already hooked this
            // module and there's no point wasting time re-hooking nothing
            if(!applied || (already && !missedOrdinals))
            {
#if ENABLED(VERBOSE_DEBUG_HOOK)
              RDCDEBUG("Stopping hooking module, %d %d %d", (int)applied, (int)already,
                       (int)missedOrdinals);
#endif
              FreeLibrary(refcountModHandle);
              return;
            }
          }

          origFirst++;
          first++;
        }
      }
      else
      {
        if(hookset)
        {
#if ENABLED(VERBOSE_DEBUG_HOOK)
          RDCDEBUG("!! Invalid IAT found for %s! %u %u", dllName, importDesc->OriginalFirstThunk,
                   importDesc->FirstThunk);
#endif
        }
      }

      importDesc++;
    }

    FreeLibrary(refcountModHandle);
  }
};

static CachedHookData *s_HookData = NULL;
static bool s_SQCYuanShenInlineHooksActive = false;
static bool s_SQCMinHookInitialised = false;
static rdcarray<void **> s_SQCInlineOriginalPointers;

static bool SQCUseYuanShenInlineHooks()
{
  if(!SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD") ||
     !SQCEnvEnabled("SQC_YUANSHEN_INLINE_HOOKS"))
    return false;

  char processPath[MAX_PATH] = {};
  GetModuleFileNameA(NULL, processPath, MAX_PATH);
  return strlower(get_basename(processPath)) == "yuanshen.exe";
}

static HMODULE SQCLoadSystemLibrary(const char *libraryName)
{
  char path[MAX_PATH] = {};
  UINT len = GetSystemDirectoryA(path, MAX_PATH);
  if(len == 0 || len >= MAX_PATH || strcat_s(path, MAX_PATH, "\\") != 0 ||
     strcat_s(path, MAX_PATH, libraryName) != 0)
    return NULL;

  return LoadLibraryA(path);
}

static bool SQCIsRequiredInlineHook(const rdcstr &libraryName, const rdcstr &functionName)
{
  if(libraryName == "d3d11.dll")
    return functionName == "D3D11CreateDevice" ||
           functionName == "D3D11CreateDeviceAndSwapChain";

  if(libraryName == "dxgi.dll")
    return functionName == "CreateDXGIFactory" || functionName == "CreateDXGIFactory1" ||
           functionName == "CreateDXGIFactory2";

  return false;
}

static void SQCResetInlineOriginalPointers()
{
  for(void **original : s_SQCInlineOriginalPointers)
  {
    if(original != NULL)
      *original = NULL;
  }

  s_SQCInlineOriginalPointers.clear();
}

static bool SQCRemoveYuanShenInlineHooks()
{
  if(s_SQCMinHookInitialised)
  {
    MH_STATUS disableStatus = MH_DisableHook(MH_ALL_HOOKS);
    if(disableStatus != MH_OK && disableStatus != MH_ERROR_DISABLED)
      RDCWARN("Failed to disable YuanShen inline hooks: %d", (int)disableStatus);

    MH_STATUS uninitialiseStatus = MH_Uninitialize();
    if(uninitialiseStatus != MH_OK)
    {
      RDCWARN("Failed to uninitialise YuanShen inline hooks: %d", (int)uninitialiseStatus);
      SQCChainLog("YuanShen inline cleanup incomplete; refusing IAT fallback");
      return false;
    }
  }

  s_SQCMinHookInitialised = false;
  s_SQCYuanShenInlineHooksActive = false;
  SQCResetInlineOriginalPointers();
  InterlockedExchange(&SQC_CaptureEntryHookCount, 0);
  return true;
}

static bool SQCApplyYuanShenInlineHooks()
{
  SQCChainLog("YuanShen inline hook transaction begin");

  MH_STATUS status = MH_Initialize();
  if(status != MH_OK)
  {
    char msg[128] = {};
    wsprintfA(msg, "YuanShen inline MH_Initialize failed status=%d", (int)status);
    SQCChainLog(msg);
    return false;
  }

  s_SQCMinHookInitialised = true;
  size_t createdHooks = 0;

  for(const char *libraryName : {"d3d11.dll", "dxgi.dll"})
  {
    auto hooksetIt = s_HookData->DllHooks.find(libraryName);
    if(hooksetIt == s_HookData->DllHooks.end())
    {
      SQCChainLog("YuanShen inline required hook library was not registered");
      SQCRemoveYuanShenInlineHooks();
      return false;
    }

    HMODULE module = SQCLoadSystemLibrary(libraryName);
    if(module == NULL)
    {
      SQCChainLog("YuanShen inline failed to load a system graphics library");
      SQCRemoveYuanShenInlineHooks();
      return false;
    }

    DllHookset &hookset = hooksetIt->second;
    hookset.module = module;
    hookset.hooksfetched = true;

    for(FunctionHook &hook : hookset.FunctionHooks)
    {
      if(!SQCIsRequiredInlineHook(hooksetIt->first, hook.function))
        continue;

      if(hook.orig == NULL || hook.hook == NULL)
      {
        SQCChainLog("YuanShen inline hook registration is incomplete");
        SQCRemoveYuanShenInlineHooks();
        return false;
      }

      FARPROC target = GetProcAddress(module, hook.function.c_str());
      if(target == NULL)
      {
        SQCChainLog("YuanShen inline required export was not found");
        SQCRemoveYuanShenInlineHooks();
        return false;
      }

      status = MH_CreateHook((LPVOID)target, hook.hook, (LPVOID *)hook.orig);
      if(status != MH_OK)
      {
        char msg[256] = {};
        wsprintfA(msg, "YuanShen inline MH_CreateHook failed function=%s status=%d",
                  hook.function.c_str(), (int)status);
        SQCChainLog(msg);
        SQCRemoveYuanShenInlineHooks();
        return false;
      }

      s_SQCInlineOriginalPointers.push_back(hook.orig);
      createdHooks++;
    }
  }

  if(createdHooks != 5)
  {
    SQCChainLog("YuanShen inline hook transaction did not create all five hooks");
    SQCRemoveYuanShenInlineHooks();
    return false;
  }

  status = MH_EnableHook(MH_ALL_HOOKS);
  if(status != MH_OK)
  {
    char msg[128] = {};
    wsprintfA(msg, "YuanShen inline MH_EnableHook failed status=%d", (int)status);
    SQCChainLog(msg);
    SQCRemoveYuanShenInlineHooks();
    return false;
  }

  s_SQCYuanShenInlineHooksActive = true;
  InterlockedExchange(&SQC_CaptureEntryHookCount, (LONG)createdHooks);
  SQCChainLog("YuanShen inline hook transaction committed hooks=5");
  return true;
}

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

static void ForAllModules(std::function<void(const MODULEENTRY32 &me32)> callback)
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE;

  // up to 10 retries
  for(int i = 0; i < 10; i++)
  {
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

    if(hModuleSnap == INVALID_HANDLE_VALUE)
    {
      DWORD err = GetLastError();

      RDCWARN("CreateToolhelp32Snapshot() -> 0x%08x", err);

      // retry if error is ERROR_BAD_LENGTH
      if(err == ERROR_BAD_LENGTH)
        continue;
    }

    // didn't retry, or succeeded
    break;
  }

  if(hModuleSnap == INVALID_HANDLE_VALUE)
  {
    RDCERR("Couldn't create toolhelp dump of modules in process");
    return;
  }

  MODULEENTRY32 me32;
  RDCEraseEl(me32);
  me32.dwSize = sizeof(MODULEENTRY32);

  BOOL success = Module32First(hModuleSnap, &me32);

  if(success == FALSE)
  {
    DWORD err = GetLastError();

    RDCERR("Couldn't get first module in process: 0x%08x", err);
    CloseHandle(hModuleSnap);
    return;
  }

  do
  {
    callback(me32);
  } while(Module32Next(hModuleSnap, &me32));

  CloseHandle(hModuleSnap);
}

static void HookAllModules()
{
  if(!s_HookData->hookAll)
    return;

  ForAllModules(
      [](const MODULEENTRY32 &me32) { s_HookData->ApplyHooks(me32.szModule, me32.hModule); });

  // check if we're already in this section of code, and if so don't go in again.
  int32_t prev = Atomic::CmpExch32(&s_HookData->posthooking, 0, 1);

  if(prev != 0)
    return;

  // for all loaded modules, call callbacks now
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
  {
    if(it->second.module == NULL)
      continue;

    if(!it->second.hooksfetched)
    {
      it->second.hooksfetched = true;

      // fetch all function hooks here, if we didn't above (perhaps because this library was
      // late-loaded)
      for(FunctionHook &hook : it->second.FunctionHooks)
      {
        if(hook.orig && *hook.orig == NULL)
          *hook.orig = FetchOriginalFunction(it->second.module, hook);
      }
    }

    rdcarray<FunctionLoadCallback> callbacks;
    // don't call callbacks next time
    callbacks.swap(it->second.Callbacks);

    for(FunctionLoadCallback cb : callbacks)
      if(cb)
        cb(it->second.module, it->first.c_str());
  }

  Atomic::CmpExch32(&s_HookData->posthooking, 1, 0);
}

static bool IsAPISet(const wchar_t *filename)
{
  if(wcschr(filename, L'/') != 0 || wcschr(filename, L'\\') != 0)
    return false;

  wchar_t match[] = L"api-ms-win";

  if(wcslen(filename) < ARRAY_COUNT(match) - 1)
    return false;

  for(size_t i = 0; i < ARRAY_COUNT(match) - 1; i++)
    if(towlower(filename[i]) != match[i])
      return false;

  return true;
}

static bool IsAPISet(const char *filename)
{
  size_t len = strlen(filename);
  rdcwstr wfn(len);

  // assume ASCII not UTF, just upcast plainly to wchar_t
  for(size_t i = 0; i < len; i++)
    wfn[i] = wchar_t(filename[i]);

  return IsAPISet(wfn.c_str());
}

HMODULE WINAPI Hooked_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE fileHandle, DWORD flags)
{
  if(s_SuppressHooking > 0)
    return LoadLibraryExA(lpLibFileName, fileHandle, flags);

  bool dohook = true;

  if(s_HookData->libraryIntercept)
  {
    HMODULE ret = s_HookData->libraryIntercept(lpLibFileName, fileHandle, flags);
    if(ret)
      return ret;
    dohook = false;
  }

  if(flags == 0 && GetModuleHandleA(lpLibFileName))
    dohook = false;

  SetLastError(S_OK);

  // we can use the function naked, as when setting up the hook for LoadLibraryExA, our own module
  // was excluded from IAT patching
  HMODULE mod = LoadLibraryExA(lpLibFileName, fileHandle, flags);

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("LoadLibraryA(%s)", lpLibFileName);
#endif

  DWORD err = GetLastError();

  if(dohook && mod && !IsAPISet(lpLibFileName))
    HookAllModules();

  SetLastError(err);

  return mod;
}

HMODULE WINAPI Hooked_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE fileHandle, DWORD flags)
{
  if(s_SuppressHooking > 0)
    return LoadLibraryExW(lpLibFileName, fileHandle, flags);

  bool dohook = true;

  if(s_HookData->libraryIntercept)
  {
    HMODULE ret =
        s_HookData->libraryIntercept(StringFormat::Wide2UTF8(lpLibFileName), fileHandle, flags);
    if(ret)
      return ret;
    dohook = false;
  }

  DWORD flagsExcludingSearchOrders = flags;

  // if this is a pure "filename.dll" load, don't care about search-order flags since loaded DLLs are
  // always returned first regardless of the search order and so we can detect the DLL is already loaded
  if(wcschr(lpLibFileName, L'\\') == 0 && wcschr(lpLibFileName, L'/') == 0)
  {
    flagsExcludingSearchOrders &= ~(LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                    LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_WITH_ALTERED_SEARCH_PATH);

#ifdef LOAD_LIBRARY_SAFE_CURRENT_DIRS
    flagsExcludingSearchOrders &= ~LOAD_LIBRARY_SAFE_CURRENT_DIRS;
#endif
  }

  // if there are no flags (possibly with search path flags excluded) and we already have the
  // library loaded, don't hook anything
  if(flagsExcludingSearchOrders == 0 && GetModuleHandleW(lpLibFileName))
    dohook = false;

  if(flags & (LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE))
    dohook = false;

  SetLastError(S_OK);

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("LoadLibraryW(%ls)", lpLibFileName);
#endif

  // we can use the function naked, as when setting up the hook for LoadLibraryExA, our own module
  // was excluded from IAT patching
  HMODULE mod = LoadLibraryExW(lpLibFileName, fileHandle, flags);

  DWORD err = GetLastError();

  if(dohook && mod && !IsAPISet(lpLibFileName))
    HookAllModules();

  SetLastError(err);

  return mod;
}

HMODULE WINAPI Hooked_LoadLibraryA(LPCSTR lpLibFileName)
{
  return Hooked_LoadLibraryExA(lpLibFileName, NULL, 0);
}

HMODULE WINAPI Hooked_LoadLibraryW(LPCWSTR lpLibFileName)
{
  return Hooked_LoadLibraryExW(lpLibFileName, NULL, 0);
}

static bool OrdinalAsString(void *func)
{
  return uint64_t(func) <= 0xffff;
}

FARPROC WINAPI Hooked_GetProcAddress(HMODULE mod, LPCSTR func)
{
  if(s_SuppressHooking > 0)
    return GetProcAddress(mod, func);

  if(mod == NULL || func == NULL || mod == s_HookData->ownmodule)
    return GetProcAddress(mod, func);

#if ENABLED(VERBOSE_DEBUG_HOOK)
  if(OrdinalAsString((void *)func))
    RDCDEBUG("Hooked_GetProcAddress(%p, %p)", mod, func);
  else
    RDCDEBUG("Hooked_GetProcAddress(%p, %s)", mod, func);
#endif

  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
  {
    if(it->second.module == NULL)
    {
      it->second.module = GetModuleHandleA(it->first.c_str());
      if(it->second.module)
      {
        // fetch all function hooks here, since we want to fill out the original function pointer
        // even in case nothing imports from that function (which means it would not get filled
        // out through FunctionHook::ApplyHook)
        for(FunctionHook &hook : it->second.FunctionHooks)
        {
          if(hook.orig && *hook.orig == NULL)
            *hook.orig = FetchOriginalFunction(it->second.module, hook);
        }

        it->second.FetchOrdinalNames();
      }
    }

    bool match = (mod == it->second.module);

    if(!match && !it->second.altmodules.empty())
    {
      for(size_t i = 0; !match && i < it->second.altmodules.size(); i++)
        match = (mod == it->second.altmodules[i]);
    }

    if(match)
    {
#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("Located module %s", it->first.c_str());
#endif

      if(OrdinalAsString((void *)func))
      {
#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Ordinal hook");
#endif

        uint32_t ordinal = (uint16_t)(uintptr_t(func) & 0xffff);

        if(ordinal < it->second.OrdinalBase)
        {
          RDCERR("Unexpected ordinal - lower than ordinalbase %u for %s",
                 (uint32_t)it->second.OrdinalBase, it->first.c_str());

          SetLastError(S_OK);
          return GetProcAddress(mod, func);
        }

        ordinal -= it->second.OrdinalBase;

        if(ordinal >= it->second.OrdinalNames.size())
        {
          RDCERR("Unexpected ordinal - higher than fetched ordinal names (%u) for %s",
                 (uint32_t)it->second.OrdinalNames.size(), it->first.c_str());

          SetLastError(S_OK);
          return GetProcAddress(mod, func);
        }

        func = it->second.OrdinalNames[ordinal].c_str();

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("found ordinal %s", func);
#endif
      }

      FunctionHook search(func, NULL, NULL);

      auto found =
          std::lower_bound(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end(), search);
      if(found != it->second.FunctionHooks.end() && !(search < *found))
      {
        FARPROC realfunc = NULL;
        {
          ScopedSuppressHooking suppress;
          realfunc = GetProcAddress(mod, func);
        }

        if(!_stricmp(it->first.c_str(), "dxgi.dll") && IsDXGIFactoryFunction(func) &&
           SQCEnvEnabled("SQC_DXGI_GETPROC_BYPASS"))
        {
          static bool loggedFactory = false;
          static bool loggedFactory1 = false;
          static bool loggedFactory2 = false;
          bool *logged = !_stricmp(func, "CreateDXGIFactory")     ? &loggedFactory
                         : !_stricmp(func, "CreateDXGIFactory1") ? &loggedFactory1
                                                                  : &loggedFactory2;

          if(!*logged)
          {
            char msg[512] = {};
            wsprintfA(msg, "Hooked_GetProcAddress bypass DXGI factory function=%s real=%p hook=%p",
                      func, realfunc, found->hook);
            SQCChainLog(msg);
            *logged = true;
          }

          SetLastError(S_OK);
          return realfunc;
        }

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Found hooked function, returning hook pointer %p", found->hook);
#endif

        SetLastError(S_OK);

        if(realfunc == NULL)
          return NULL;

        return (FARPROC)found->hook;
      }
    }
  }

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("No matching hook found, returning original");
#endif

  SetLastError(S_OK);

  return GetProcAddress(mod, func);
}
static void InitHookData()
{
  if(!s_HookData)
  {
    s_HookData = new CachedHookData;

    RDCASSERT(s_HookData->DllHooks.empty());

    const bool lightHooks = SQCEnvEnabled("SQC_D3D11_LIGHT_HOOKS");
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryA", NULL, &Hooked_LoadLibraryA));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryW", NULL, &Hooked_LoadLibraryW));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryExA", NULL, &Hooked_LoadLibraryExA));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryExW", NULL, &Hooked_LoadLibraryExW));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("GetProcAddress", NULL, &Hooked_GetProcAddress));

    for(const char *apiset :
        {"api-ms-win-core-libraryloader-l1-1-0.dll", "api-ms-win-core-libraryloader-l1-1-1.dll",
         "api-ms-win-core-libraryloader-l1-1-2.dll", "api-ms-win-core-libraryloader-l1-2-0.dll",
         "api-ms-win-core-libraryloader-l1-2-1.dll"})
    {
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryA", NULL, &Hooked_LoadLibraryA));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryW", NULL, &Hooked_LoadLibraryW));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryExA", NULL, &Hooked_LoadLibraryExA));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryExW", NULL, &Hooked_LoadLibraryExW));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("GetProcAddress", NULL, &Hooked_GetProcAddress));
    }

    if(lightHooks)
      SQCChainLog("InitHookData light mode loader notifications enabled; API hooks limited");

    GetModuleHandleEx(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCTSTR)&s_HookData, &s_HookData->ownmodule);
  }
}

void LibraryHooks::RegisterFunctionHook(const char *libraryName, const FunctionHook &hook)
{
  if(!_stricmp(libraryName, "kernel32.dll"))
  {
    if(hook.function == "LoadLibraryA" || hook.function == "LoadLibraryW" ||
       hook.function == "LoadLibraryExA" || hook.function == "LoadLibraryExW" ||
       hook.function == "GetProcAddress")
    {
      RDCERR("Cannot hook LoadLibrary* or GetProcAddress, as these are hooked internally");
      return;
    }
  }

  if(!SQCAllowLightHookLibrary(libraryName))
  {
    char msg[256] = {};
    wsprintfA(msg, "RegisterFunctionHook light skip library=%s function=%s", libraryName,
              hook.function.c_str());
    SQCChainLog(msg);
    return;
  }

  s_HookData->DllHooks[strlower(rdcstr(libraryName))].FunctionHooks.push_back(hook);

  if(hook.function == "D3D11CreateDevice" ||
     hook.function == "D3D11CreateDeviceAndSwapChain" ||
     hook.function == "CreateDXGIFactory" || hook.function == "CreateDXGIFactory1" ||
     hook.function == "CreateDXGIFactory2")
  {
    char msg[256] = {};
    wsprintfA(msg, "RegisterFunctionHook library=%s function=%s", libraryName,
              hook.function.c_str());
    SQCChainLog(msg);
  }
}

void LibraryHooks::RegisterLibraryHook(const char *libraryName, FunctionLoadCallback loadedCallback)
{
  if(!SQCAllowLightHookLibrary(libraryName))
  {
    char msg[256] = {};
    wsprintfA(msg, "RegisterLibraryHook light skip library=%s", libraryName);
    SQCChainLog(msg);
    return;
  }

  s_HookData->DllHooks[strlower(rdcstr(libraryName))].Callbacks.push_back(loadedCallback);
}

void LibraryHooks::IgnoreLibrary(const char *libraryName)
{
  rdcstr lowername = libraryName;

  for(size_t i = 0; i < lowername.size(); i++)
    lowername[i] = (char)tolower(lowername[i]);

  s_HookData->ignores.insert(lowername);
}

void LibraryHooks::BeginHookRegistration()
{
  SQCChainLog("BeginHookRegistration");
  InterlockedExchange(&SQC_CaptureEntryHookCount, 0);
  InitHookData();
}

bool LibraryHooks::HooksApplied()
{
  return InterlockedCompareExchange(&SQC_CaptureEntryHookCount, 0, 0) > 0;
}

// hook all functions for currently loaded modules.
// some of these hooks (as above) will hook LoadLibrary/GetProcAddress, to protect
void LibraryHooks::EndHookRegistration()
{
  SQCChainLog("EndHookRegistration begin");
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
    std::sort(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end());

  if(SQCUseYuanShenInlineHooks())
  {
    if(SQCApplyYuanShenInlineHooks())
    {
      // Inline hooks cover dynamically resolved graphics exports directly. Do not modify the main
      // executable's loader IAT in this mode; that mutation is what correlated with the startup
      // exception loop in the captured YuanShen diagnostics.
      SQCChainLog("EndHookRegistration YuanShen inline-only path committed");
      return;
    }

    // The old light-mode fallback patches GetProcAddress in the main executable. Runtime evidence
    // ties that mutation to the repeated startup exception loop, so a failed inline transaction
    // must be reported as HooksFailed instead of silently restoring the known-slow path.
    SQCChainLog("EndHookRegistration YuanShen inline path failed; IAT fallback blocked");
    return;
  }

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("Applying hooks");
#endif

  HookAllModules();
  SQCChainLog("EndHookRegistration after first HookAllModules");

  if(s_HookData->missedOrdinals)
  {
#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("Missed ordinals - applying hooks again");
#endif

    // we need to do a second pass now that we know ordinal names to finally hook
    // some imports by ordinal only.
    HookAllModules();

    s_HookData->missedOrdinals = false;
    SQCChainLog("EndHookRegistration after ordinal retry");
  }

  SQCChainLog("EndHookRegistration done");
}

void LibraryHooks::Refresh()
{
  // don't need to refresh on windows
}

void LibraryHooks::ReplayInitialise()
{
}

void LibraryHooks::RemoveHooks()
{
  LibraryHooks::RemoveHookCallbacks();

  if(s_SQCYuanShenInlineHooksActive || s_SQCMinHookInitialised)
    SQCRemoveYuanShenInlineHooks();

  for(auto it = s_InstalledHooks.begin(); it != s_InstalledHooks.end(); ++it)
  {
    DWORD oldProtection = PAGE_EXECUTE;

    void **IATentry = it->first;

    BOOL success = VirtualProtect(IATentry, sizeof(void *), PAGE_READWRITE, &oldProtection);
    if(!success)
    {
      RDCERR("Failed to make IAT entry writeable 0x%p", IATentry);
      continue;
    }

    *IATentry = it->second;

    success = VirtualProtect(IATentry, sizeof(void *), oldProtection, &oldProtection);
    if(!success)
    {
      RDCERR("Failed to restore IAT entry protection 0x%p", IATentry);
      continue;
    }
  }
}

bool LibraryHooks::Detect(const char *identifier)
{
  bool ret = false;
  ForAllModules([&ret, identifier](const MODULEENTRY32 &me32) {
    if(GetProcAddress(me32.hModule, identifier) != NULL)
      ret = true;
  });
  return ret;
}

void Win32_RegisterManualModuleHooking()
{
  InitHookData();

  s_HookData->hookAll = false;
}

void Win32_InterceptLibraryLoads(std::function<HMODULE(const rdcstr &, HANDLE, DWORD)> callback)
{
  s_HookData->libraryIntercept = callback;
}

void Win32_ManualHookModule(rdcstr modName, HMODULE module)
{
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
    std::sort(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end());

  modName = strlower(modName);

  s_HookData->DllHooks[modName].module = module;

  for(FunctionHook &hook : s_HookData->DllHooks[modName].FunctionHooks)
  {
    if(hook.orig)
      *hook.orig = FetchOriginalFunction(module, hook);
  }

  s_HookData->ApplyHooks(modName.c_str(), module);
}

// android only hooking functions, not used on win32
ScopedSuppressHooking::ScopedSuppressHooking()
{
  s_SuppressHooking++;
}

ScopedSuppressHooking::~ScopedSuppressHooking()
{
  s_SuppressHooking--;
}
