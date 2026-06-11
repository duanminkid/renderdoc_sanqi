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

#include "d3d11_hooks.h"
#include "driver/dxgi/dxgi_wrapped.h"
#include "hooks/hooks.h"
#include "d3d11_device.h"

static void SQCChainLog(const char *msg)
{
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

static FARPROC GetRawExport(HMODULE module, const char *name)
{
  if(module == NULL || name == NULL)
    return NULL;

  byte *baseAddress = (byte *)module;
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)baseAddress;
  if(dos->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(baseAddress + dos->e_lfanew);
  if(nt->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  IMAGE_DATA_DIRECTORY exportDir =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if(exportDir.VirtualAddress == 0 || exportDir.Size == 0)
    return NULL;

  PIMAGE_EXPORT_DIRECTORY exports =
      (PIMAGE_EXPORT_DIRECTORY)(baseAddress + exportDir.VirtualAddress);
  DWORD *names = (DWORD *)(baseAddress + exports->AddressOfNames);
  WORD *ordinals = (WORD *)(baseAddress + exports->AddressOfNameOrdinals);
  DWORD *functions = (DWORD *)(baseAddress + exports->AddressOfFunctions);

  for(DWORD i = 0; i < exports->NumberOfNames; i++)
  {
    const char *exportName = (const char *)(baseAddress + names[i]);
    if(strcmp(exportName, name) != 0)
      continue;

    DWORD rva = functions[ordinals[i]];
    if(rva >= exportDir.VirtualAddress && rva < exportDir.VirtualAddress + exportDir.Size)
      return NULL;

    return (FARPROC)(baseAddress + rva);
  }

  return NULL;
}

static bool IsOwnModuleProc(FARPROC proc)
{
  if(proc == NULL)
    return false;

  HMODULE procModule = NULL;
  if(!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         (LPCSTR)proc, &procModule))
    return false;

  HMODULE selfModule = NULL;
  GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                     (LPCSTR)&SQCChainLog, &selfModule);

  return procModule != NULL && procModule == selfModule;
}

static FARPROC GetSystemD3D11Proc(const char *name)
{
  static HMODULE d3d11 = NULL;

  ScopedSuppressHooking suppress;

  if(d3d11 == NULL)
  {
    char path[MAX_PATH] = {};
    UINT len = GetSystemDirectoryA(path, MAX_PATH);
    if(len > 0 && len < MAX_PATH)
    {
      strcat_s(path, MAX_PATH, "\\d3d11.dll");
      d3d11 = LoadLibraryA(path);
    }

    if(d3d11 == NULL)
      d3d11 = LoadLibraryA("d3d11.dll");
  }

  FARPROC proc = GetRawExport(d3d11, name);
  if(proc == NULL)
    proc = d3d11 ? GetProcAddress(d3d11, name) : NULL;

  char msg[256] = {};
  wsprintfA(msg, "GetSystemD3D11Proc name=%s module=%p proc=%p", name, d3d11, proc);
  SQCChainLog(msg);

  return proc;
}

ID3DDevice *GetD3D11DeviceIfAlloc(IUnknown *dev)
{
  if(WrappedID3D11Device::IsAlloc(dev))
    return (WrappedID3D11Device *)dev;

  return NULL;
}

class D3D11Hook : LibraryHook
{
public:
  void RegisterHooks()
  {
    SQCChainLog("D3D11Hook::RegisterHooks");
    RDCLOG("Registering D3D11 hooks");

    WrappedIDXGISwapChain4::RegisterD3DDeviceCallback(GetD3D11DeviceIfAlloc);

    // also require d3dcompiler_??.dll
    if(GetD3DCompiler() == NULL)
    {
      RDCERR("Failed to load d3dcompiler_??.dll - not inserting D3D11 hooks.");
      return;
    }

    LibraryHooks::RegisterLibraryHook("d3d11.dll", NULL);

    CreateDevice.Register("d3d11.dll", "D3D11CreateDevice", D3D11CreateDevice_hook);
    CreateDeviceAndSwapChain.Register("d3d11.dll", "D3D11CreateDeviceAndSwapChain",
                                      D3D11CreateDeviceAndSwapChain_hook);

    m_RecurseSlot = Threading::AllocateTLSSlot();
    Threading::SetTLSValue(m_RecurseSlot, NULL);
  }

private:
  static D3D11Hook d3d11hooks;

  HookedFunction<PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN> CreateDeviceAndSwapChain;
  HookedFunction<PFN_D3D11_CREATE_DEVICE> CreateDevice;

  // re-entrancy detection (can happen in rare cases with e.g. fraps)
  uint64_t m_RecurseSlot = 0;

  void EndRecurse() { Threading::SetTLSValue(m_RecurseSlot, NULL); }
  bool CheckRecurse()
  {
    if(Threading::GetTLSValue(m_RecurseSlot) == NULL)
    {
      Threading::SetTLSValue(m_RecurseSlot, (void *)1);
      return false;
    }

    return true;
  }

  friend HRESULT CreateD3D11_Internal(RealD3D11CreateFunction real, __in_opt IDXGIAdapter *pAdapter,
                                      D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
                                      __in_ecount_opt(FeatureLevels)
                                          CONST D3D_FEATURE_LEVEL *pFeatureLevels,
                                      UINT FeatureLevels, UINT SDKVersion,
                                      __in_opt CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
                                      __out_opt IDXGISwapChain **ppSwapChain,
                                      __out_opt ID3D11Device **ppDevice,
                                      __out_opt D3D_FEATURE_LEVEL *pFeatureLevel,
                                      __out_opt ID3D11DeviceContext **ppImmediateContext);

  HRESULT Create_Internal(RealD3D11CreateFunction real, __in_opt IDXGIAdapter *pAdapter,
                          D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
                          __in_ecount_opt(FeatureLevels) CONST D3D_FEATURE_LEVEL *pFeatureLevels,
                          UINT FeatureLevels, UINT SDKVersion,
                          __in_opt CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
                          __out_opt IDXGISwapChain **ppSwapChain, __out_opt ID3D11Device **ppDevice,
                          __out_opt D3D_FEATURE_LEVEL *pFeatureLevel,
                          __out_opt ID3D11DeviceContext **ppImmediateContext)
  {
    // if we're already inside a wrapped create, then DON'T do anything special. Just call onwards
    if(CheckRecurse())
    {
      SQCChainLog("D3D11 Create_Internal recurse passthrough");
      return real(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
                  pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
    }

    RDCDEBUG("Call to Create_Internal Flags %x", Flags);
    {
      char msg[256] = {};
      wsprintfA(msg, "D3D11 Create_Internal begin flags=0x%X swap=%p ppDevice=%p ppCtx=%p", Flags,
                pSwapChainDesc, ppDevice, ppImmediateContext);
      SQCChainLog(msg);
    }

    // we should no longer go through here in the replay application
    RDCASSERT(!SanQiCapture::Inst().IsReplayApp());

    if(SanQiCapture::Inst().GetCaptureOptions().apiValidation)
      Flags |= D3D11_CREATE_DEVICE_DEBUG;
    else
      Flags &= ~D3D11_CREATE_DEVICE_DEBUG;

    DXGI_SWAP_CHAIN_DESC swapDesc;
    DXGI_SWAP_CHAIN_DESC *pUsedSwapDesc = NULL;

    if(pSwapChainDesc)
    {
      swapDesc = *pSwapChainDesc;
      pUsedSwapDesc = &swapDesc;
    }

    if(pUsedSwapDesc && !SanQiCapture::Inst().GetCaptureOptions().allowFullscreen)
    {
      pUsedSwapDesc->Windowed = TRUE;
      SQCChainLog("D3D11 Create_Internal forced windowed swapchain");
    }

    RDCDEBUG("Calling real createdevice...");
    SQCChainLog("D3D11 before real CreateDevice");

    // Hack for D3DGear which crashes if ppDevice is NULL
    ID3D11Device *dummydev = NULL;
    bool dummyUsed = false;
    if(ppDevice == NULL)
    {
      ppDevice = &dummydev;
      dummyUsed = true;
    }

    HRESULT ret = E_FAIL;
    {
      ScopedSuppressHooking suppress;
      ret = real(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
                 pUsedSwapDesc, ppSwapChain, ppDevice, pFeatureLevel, NULL);
    }
    {
      char msg[256] = {};
      wsprintfA(msg, "D3D11 after real CreateDevice hr=0x%08X device=%p swapchain=%p",
                (unsigned int)ret, ppDevice ? *ppDevice : NULL,
                ppSwapChain ? *ppSwapChain : NULL);
      SQCChainLog(msg);
    }

    SAFE_RELEASE(dummydev);
    if(dummyUsed)
      ppDevice = NULL;

    RDCDEBUG("Called real createdevice...");

    bool suppress = false;

    suppress = (Flags & D3D11_CREATE_DEVICE_PREVENT_ALTERING_LAYER_SETTINGS_FROM_REGISTRY) != 0;

    if(suppress)
    {
      RDCLOG("Application requested not to be hooked.");
    }
    else if(SUCCEEDED(ret) && ppDevice)
    {
      RDCDEBUG("succeeded and hooking.");

      if(!WrappedID3D11Device::IsAlloc(*ppDevice))
      {
        SQCChainLog("D3D11 before WrappedID3D11Device");
        D3D11InitParams params;
        params.DriverType = DriverType;
        params.Flags = Flags;
        params.SDKVersion = SDKVersion;
        params.NumFeatureLevels = FeatureLevels;
        if(FeatureLevels > 0)
          memcpy(params.FeatureLevels, pFeatureLevels, sizeof(D3D_FEATURE_LEVEL) * FeatureLevels);

        WrappedID3D11Device *wrap = new WrappedID3D11Device(*ppDevice, params);

        RDCDEBUG("created wrapped device.");
        SQCChainLog("D3D11 after WrappedID3D11Device");

        *ppDevice = wrap;

        SQCChainLog("D3D11 before GetImmediateContext");
        wrap->GetImmediateContext(ppImmediateContext);
        SQCChainLog("D3D11 after GetImmediateContext");

        if(ppSwapChain && *ppSwapChain)
        {
          SQCChainLog("D3D11 before WrappedIDXGISwapChain4");
          *ppSwapChain = new WrappedIDXGISwapChain4(
              *ppSwapChain, pSwapChainDesc ? pSwapChainDesc->OutputWindow : NULL, wrap);
          SQCChainLog("D3D11 after WrappedIDXGISwapChain4");
        }
      }
    }
    else if(SUCCEEDED(ret))
    {
      RDCLOG("Created wrapped D3D11 device.");
    }
    else
    {
      RDCDEBUG("failed. HRESULT: %s", ToStr(ret).c_str());
    }

    EndRecurse();
    SQCChainLog("D3D11 Create_Internal end");

    return ret;
  }

  static HRESULT WINAPI D3D11CreateDevice_hook(
      __in_opt IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
      __in_ecount_opt(FeatureLevels) CONST D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels,
      UINT SDKVersion, __out_opt ID3D11Device **ppDevice,
      __out_opt D3D_FEATURE_LEVEL *pFeatureLevel, __out_opt ID3D11DeviceContext **ppImmediateContext)
  {
    SQCChainLog("D3D11CreateDevice_hook hit");
    // just forward the call with NULL swapchain parameters
    return D3D11CreateDeviceAndSwapChain_hook(pAdapter, DriverType, Software, Flags, pFeatureLevels,
                                              FeatureLevels, SDKVersion, NULL, NULL, ppDevice,
                                              pFeatureLevel, ppImmediateContext);
  }

  static HRESULT WINAPI D3D11CreateDeviceAndSwapChain_hook(
      __in_opt IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
      __in_ecount_opt(FeatureLevels) CONST D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels,
      UINT SDKVersion, __in_opt CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
      __out_opt IDXGISwapChain **ppSwapChain, __out_opt ID3D11Device **ppDevice,
      __out_opt D3D_FEATURE_LEVEL *pFeatureLevel, __out_opt ID3D11DeviceContext **ppImmediateContext)
  {
    static thread_local bool hookRecurse = false;
    SQCChainLog("D3D11CreateDeviceAndSwapChain_hook hit");

    if(hookRecurse)
    {
      SQCChainLog("D3D11CreateDeviceAndSwapChain recursion raw passthrough");
      PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN real =
          (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)GetSystemD3D11Proc(
              "D3D11CreateDeviceAndSwapChain");
      if(real != NULL && real != &D3D11CreateDeviceAndSwapChain_hook &&
         !IsOwnModuleProc((FARPROC)real))
      {
        ScopedSuppressHooking suppress;
        return real(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                    SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel,
                    ppImmediateContext);
      }

      SQCChainLog("D3D11CreateDeviceAndSwapChain recursion no raw target");
      return E_FAIL;
    }

    PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN saved = d3d11hooks.CreateDeviceAndSwapChain();
    PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN createFunc =
        (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)GetSystemD3D11Proc(
            "D3D11CreateDeviceAndSwapChain");
    {
      char msg[256] = {};
      wsprintfA(msg, "D3D11CreateDeviceAndSwapChain saved=%p system=%p", saved, createFunc);
      SQCChainLog(msg);
    }

    if(createFunc == NULL || createFunc == &D3D11CreateDeviceAndSwapChain_hook ||
       IsOwnModuleProc((FARPROC)createFunc))
    {
      RDCWARN("Call to D3D11CreateDeviceAndSwapChain_hook without valid system export");
      SQCChainLog("D3D11CreateDeviceAndSwapChain system export invalid, trying saved onward");
      createFunc = saved;
    }

    // shouldn't ever get here, we should either have it from procaddress or the hook function, but
    // let's be safe.
    if(createFunc == NULL || createFunc == &D3D11CreateDeviceAndSwapChain_hook ||
       IsOwnModuleProc((FARPROC)createFunc))
    {
      RDCERR("Something went seriously wrong with the hooks!");
      SQCChainLog("D3D11CreateDeviceAndSwapChain no valid real target");
      return E_UNEXPECTED;
    }

    hookRecurse = true;
    HRESULT ret = d3d11hooks.Create_Internal(createFunc, pAdapter, DriverType, Software, Flags,
                                             pFeatureLevels, FeatureLevels, SDKVersion,
                                             pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel,
                                             ppImmediateContext);
    hookRecurse = false;
    return ret;
  }
};

D3D11Hook D3D11Hook::d3d11hooks;

HRESULT CreateD3D11_Internal(RealD3D11CreateFunction real, __in_opt IDXGIAdapter *pAdapter,
                             D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
                             __in_ecount_opt(FeatureLevels) CONST D3D_FEATURE_LEVEL *pFeatureLevels,
                             UINT FeatureLevels, UINT SDKVersion,
                             __in_opt CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
                             __out_opt IDXGISwapChain **ppSwapChain,
                             __out_opt ID3D11Device **ppDevice,
                             __out_opt D3D_FEATURE_LEVEL *pFeatureLevel,
                             __out_opt ID3D11DeviceContext **ppImmediateContext)
{
  return D3D11Hook::d3d11hooks.Create_Internal(
      real, pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
      pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
}
