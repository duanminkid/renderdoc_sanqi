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
#include "core/core.h"
#include "driver/dxgi/dxgi_wrapped.h"
#include "hooks/hooks.h"
#include "d3d11_device.h"

static volatile LONG SQC_D3D11HooksRegistered = 0;

bool D3D11HooksRegistered()
{
  return InterlockedCompareExchange(&SQC_D3D11HooksRegistered, 0, 0) != 0;
}

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

static bool SQCEnvEnabled(const char *name)
{
  char value[16] = {};
  DWORD len = GetEnvironmentVariableA(name, value, sizeof(value));
  return len > 0 && _stricmp(value, "0") != 0 && _stricmp(value, "false") != 0 &&
         _stricmp(value, "off") != 0;
}

static bool SQCIsYuanShenProcess()
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

  return _wcsicmp(base, L"YuanShen.exe") == 0;
}

static bool SQCUseYuanShenInlineHooks()
{
  return SQCIsYuanShenProcess() && SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD") &&
         SQCEnvEnabled("SQC_YUANSHEN_INLINE_HOOKS");
}

static thread_local bool s_SQCD3D11InlineCall = false;

struct SQCScopedD3D11InlineCall
{
  explicit SQCScopedD3D11InlineCall(bool enabled)
      : m_Enabled(enabled), m_Previous(s_SQCD3D11InlineCall)
  {
    if(m_Enabled)
      s_SQCD3D11InlineCall = true;
  }

  ~SQCScopedD3D11InlineCall()
  {
    if(m_Enabled)
      s_SQCD3D11InlineCall = m_Previous;
  }

private:
  bool m_Enabled;
  bool m_Previous;
};

static bool SQCSwapchainReturnWrapperEnabled()
{
  if(SQCIsYuanShenProcess() && SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD") &&
     !SQCEnvEnabled("SQC_YUANSHEN_SWAPCHAIN_WRAP"))
    return false;

  return true;
}

typedef HRESULT(STDMETHODCALLTYPE *SQC_IDXGISwapChain_Present)(IDXGISwapChain *swapchain,
                                                               UINT syncInterval, UINT flags);
typedef HRESULT(STDMETHODCALLTYPE *SQC_IDXGISwapChain1_Present1)(
    IDXGISwapChain1 *swapchain, UINT syncInterval, UINT flags,
    const DXGI_PRESENT_PARAMETERS *presentParameters);

struct SQCPassthroughSwapchain
{
  IUnknown *swapchain;
  WrappedIDXGISwapChain4 *swapper;
};

struct SQCPresentHook
{
  void **vtable;
  size_t slot;
  void *real;
};

static SRWLOCK g_SQCPassthroughSwapchainLock = SRWLOCK_INIT;
static SQCPassthroughSwapchain g_SQCPassthroughSwapchains[64] = {};
static SRWLOCK g_SQCPresentHookLock = SRWLOCK_INIT;
static SQCPresentHook g_SQCPresentHooks[32] = {};
static void SQCDrivePassthroughPresent(WrappedIDXGISwapChain4 *swapper, UINT syncInterval,
                                       UINT flags)
{
  if(swapper == NULL)
    return;

  // The original native Present remains the only swapchain submission. This advances the shadow
  // wrapper's overlay, active-driver, and capture lifecycle without submitting a second frame.
  swapper->SidecarPresent(syncInterval, flags);
}

static WrappedIDXGISwapChain4 *SQCFindPassthroughSwapper(IUnknown *swapchain)
{
  WrappedIDXGISwapChain4 *swapper = NULL;

  AcquireSRWLockShared(&g_SQCPassthroughSwapchainLock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCPassthroughSwapchains); i++)
  {
    if(g_SQCPassthroughSwapchains[i].swapchain == swapchain)
    {
      swapper = g_SQCPassthroughSwapchains[i].swapper;
      break;
    }
  }
  ReleaseSRWLockShared(&g_SQCPassthroughSwapchainLock);

  return swapper;
}

static void *SQCFindPresentReal(void **vtable, size_t slot)
{
  void *real = NULL;

  AcquireSRWLockShared(&g_SQCPresentHookLock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCPresentHooks); i++)
  {
    if(g_SQCPresentHooks[i].vtable == vtable && g_SQCPresentHooks[i].slot == slot)
    {
      real = g_SQCPresentHooks[i].real;
      break;
    }
  }
  ReleaseSRWLockShared(&g_SQCPresentHookLock);

  return real;
}

static HRESULT STDMETHODCALLTYPE SQCPresent_hook(IDXGISwapChain *swapchain, UINT syncInterval,
                                                 UINT flags)
{
  void **vtable = swapchain != NULL ? *(void ***)swapchain : NULL;
  SQC_IDXGISwapChain_Present real =
      (SQC_IDXGISwapChain_Present)SQCFindPresentReal(vtable, 8);
  if(real == NULL)
  {
    SQCChainLog("SQC passthrough Present missing real target");
    return DXGI_ERROR_INVALID_CALL;
  }

  WrappedIDXGISwapChain4 *swapper = SQCFindPassthroughSwapper(swapchain);
  SQCDrivePassthroughPresent(swapper, syncInterval, flags);

  return real(swapchain, syncInterval, flags);
}

static HRESULT STDMETHODCALLTYPE SQCPresent1_hook(
    IDXGISwapChain1 *swapchain, UINT syncInterval, UINT flags,
    const DXGI_PRESENT_PARAMETERS *presentParameters)
{
  void **vtable = swapchain != NULL ? *(void ***)swapchain : NULL;
  SQC_IDXGISwapChain1_Present1 real =
      (SQC_IDXGISwapChain1_Present1)SQCFindPresentReal(vtable, 22);
  if(real == NULL)
  {
    SQCChainLog("SQC passthrough Present1 missing real target");
    return DXGI_ERROR_INVALID_CALL;
  }

  WrappedIDXGISwapChain4 *swapper = SQCFindPassthroughSwapper(swapchain);
  SQCDrivePassthroughPresent(swapper, syncInterval, flags);

  return real(swapchain, syncInterval, flags, presentParameters);
}

static bool SQCInstallPresentHook(IUnknown *swapchain, size_t slot, void *hook, const char *name)
{
  if(swapchain == NULL || hook == NULL)
    return false;

  void **vtable = *(void ***)swapchain;
  if(vtable == NULL)
    return false;

  AcquireSRWLockExclusive(&g_SQCPresentHookLock);

  for(size_t i = 0; i < ARRAY_COUNT(g_SQCPresentHooks); i++)
  {
    if(g_SQCPresentHooks[i].vtable == vtable && g_SQCPresentHooks[i].slot == slot)
    {
      ReleaseSRWLockExclusive(&g_SQCPresentHookLock);
      return true;
    }
  }

  int freeSlot = -1;
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCPresentHooks); i++)
  {
    if(g_SQCPresentHooks[i].vtable == NULL)
    {
      freeSlot = (int)i;
      break;
    }
  }

  if(freeSlot < 0)
  {
    ReleaseSRWLockExclusive(&g_SQCPresentHookLock);
    SQCChainLog("SQC passthrough Present hook table full");
    return false;
  }

  DWORD oldProtect = 0;
  if(!VirtualProtect(&vtable[slot], sizeof(void *), PAGE_READWRITE, &oldProtect))
  {
    ReleaseSRWLockExclusive(&g_SQCPresentHookLock);
    SQCChainLog("SQC passthrough Present hook VirtualProtect failed");
    return false;
  }

  g_SQCPresentHooks[freeSlot].vtable = vtable;
  g_SQCPresentHooks[freeSlot].slot = slot;
  g_SQCPresentHooks[freeSlot].real = vtable[slot];
  vtable[slot] = hook;

  DWORD unused = 0;
  VirtualProtect(&vtable[slot], sizeof(void *), oldProtect, &unused);
  FlushInstructionCache(GetCurrentProcess(), &vtable[slot], sizeof(void *));

  ReleaseSRWLockExclusive(&g_SQCPresentHookLock);

  char msg[192] = {};
  wsprintfA(msg, "SQC passthrough Present hook installed %s vtable=%p slot=%u", name, vtable,
            (unsigned int)slot);
  SQCChainLog(msg);
  return true;
}

static void SQCStorePassthroughSwapper(IUnknown *swapchain, WrappedIDXGISwapChain4 *swapper)
{
  if(swapchain == NULL || swapper == NULL)
    return;

  swapchain->AddRef();

  AcquireSRWLockExclusive(&g_SQCPassthroughSwapchainLock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCPassthroughSwapchains); i++)
  {
    if(g_SQCPassthroughSwapchains[i].swapchain == swapchain)
    {
      ReleaseSRWLockExclusive(&g_SQCPassthroughSwapchainLock);
      swapchain->Release();
      return;
    }
  }

  for(size_t i = 0; i < ARRAY_COUNT(g_SQCPassthroughSwapchains); i++)
  {
    if(g_SQCPassthroughSwapchains[i].swapchain == NULL)
    {
      g_SQCPassthroughSwapchains[i].swapchain = swapchain;
      g_SQCPassthroughSwapchains[i].swapper = swapper;
      break;
    }
  }
  ReleaseSRWLockExclusive(&g_SQCPassthroughSwapchainLock);
}

static void SQCRegisterPassthroughSwapchainWindow(ID3DDevice *wrapDevice, HWND wnd,
                                                  IUnknown *swapchain, const char *source)
{
  if(wrapDevice == NULL || wnd == NULL || swapchain == NULL)
  {
    char msg[160] = {};
    wsprintfA(msg,
              "SQC passthrough swapchain missing registration data source=%s device=%p hwnd=%p swap=%p",
              source, wrapDevice, wnd, swapchain);
    SQCChainLog(msg);
    return;
  }

  IDXGISwapChain *swap = NULL;
  if(FAILED(swapchain->QueryInterface(__uuidof(IDXGISwapChain), (void **)&swap)) || swap == NULL)
    return;

  swap->AddRef();
  WrappedIDXGISwapChain4 *swapper = new WrappedIDXGISwapChain4(swap, wnd, wrapDevice);
  SQCStorePassthroughSwapper(swapchain, swapper);
  SQCStorePassthroughSwapper(swap, swapper);

  IDXGISwapChain1 *swap1 = NULL;
  if(SUCCEEDED(swapchain->QueryInterface(__uuidof(IDXGISwapChain1), (void **)&swap1)) &&
     swap1 != NULL)
  {
    SQCStorePassthroughSwapper(swap1, swapper);
    SQCInstallPresentHook(swap1, 22, (void *)&SQCPresent1_hook, "Present1");
    swap1->Release();
  }

  SQCInstallPresentHook(swap, 8, (void *)&SQCPresent_hook, "Present");
  swap->Release();

  char msg[192] = {};
  wsprintfA(msg, "SQC passthrough swapchain registered Present sidecar source=%s device=%p hwnd=%p",
            source, wrapDevice->GetFrameCapturerDevice(), wnd);
  SQCChainLog(msg);
}

struct SQCShadowD3D11Device
{
  IUnknown *identity;
  WrappedID3D11Device *wrapped;
};

static SRWLOCK g_SQCShadowD3D11Lock = SRWLOCK_INIT;
static SQCShadowD3D11Device g_SQCShadowD3D11Devices[64] = {};

typedef HRESULT(STDMETHODCALLTYPE *SQC_IDXGIFactory_CreateSwapChain)(
    IDXGIFactory *factory, IUnknown *device, DXGI_SWAP_CHAIN_DESC *desc,
    IDXGISwapChain **swapchain);
typedef HRESULT(STDMETHODCALLTYPE *SQC_IDXGIFactory2_CreateSwapChainForHwnd)(
    IDXGIFactory2 *factory, IUnknown *device, HWND hwnd, const DXGI_SWAP_CHAIN_DESC1 *desc,
    const DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreenDesc, IDXGIOutput *restrictToOutput,
    IDXGISwapChain1 **swapchain);
typedef HRESULT(STDMETHODCALLTYPE *SQC_IDXGIFactory2_CreateSwapChainForCoreWindow)(
    IDXGIFactory2 *factory, IUnknown *device, IUnknown *window, const DXGI_SWAP_CHAIN_DESC1 *desc,
    IDXGIOutput *restrictToOutput, IDXGISwapChain1 **swapchain);
typedef HRESULT(STDMETHODCALLTYPE *SQC_IDXGIFactory2_CreateSwapChainForComposition)(
    IDXGIFactory2 *factory, IUnknown *device, const DXGI_SWAP_CHAIN_DESC1 *desc,
    IDXGIOutput *restrictToOutput, IDXGISwapChain1 **swapchain);

struct SQCSwapchainCreateHook
{
  void **vtable;
  size_t slot;
  void *real;
};

static SRWLOCK g_SQCSwapchainCreateLock = SRWLOCK_INIT;
static SQCSwapchainCreateHook g_SQCSwapchainCreateHooks[64] = {};
static SRWLOCK g_SQCPendingFactoryLock = SRWLOCK_INIT;
static IUnknown *g_SQCPendingFactories[16] = {};

ID3DDevice *GetD3D11DeviceIfAlloc(IUnknown *dev);
static void SQCHookFactorySwapchainCreates(IUnknown *factory);
static void SQCHookPendingFactories();

typedef HRESULT(STDMETHODCALLTYPE *SQC_IDXGIAdapter_GetParent)(IDXGIAdapter *adapter, REFIID riid,
                                                               void **ppParent);

struct SQCAdapterGetParentHook
{
  void **vtable;
  SQC_IDXGIAdapter_GetParent realGetParent;
};

static SRWLOCK g_SQCAdapterGetParentLock = SRWLOCK_INIT;
static SQCAdapterGetParentHook g_SQCAdapterGetParentHooks[16] = {};

static HRESULT STDMETHODCALLTYPE SQCAdapterGetParent_hook(IDXGIAdapter *adapter, REFIID riid,
                                                          void **ppParent)
{
  void **vtable = adapter != NULL ? *(void ***)adapter : NULL;
  SQC_IDXGIAdapter_GetParent realGetParent = NULL;

  AcquireSRWLockShared(&g_SQCAdapterGetParentLock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCAdapterGetParentHooks); i++)
  {
    if(g_SQCAdapterGetParentHooks[i].vtable == vtable)
    {
      realGetParent = g_SQCAdapterGetParentHooks[i].realGetParent;
      break;
    }
  }
  ReleaseSRWLockShared(&g_SQCAdapterGetParentLock);

  if(realGetParent == NULL)
  {
    SQCChainLog("SQC DXGI adapter GetParent hook missing real target");
    return E_FAIL;
  }

  HRESULT ret = realGetParent(adapter, riid, ppParent);
  if(SUCCEEDED(ret) && ppParent != NULL && *ppParent != NULL)
  {
    SQCChainLog("SQC DXGI adapter GetParent hook hit");
    if(RefCountDXGIObject::HandleWrap("SQCAdapterGetParent", riid, ppParent))
      SQCChainLog("SQC DXGI adapter GetParent wrapped parent");
  }

  return ret;
}

static void SQCHookAdapterGetParent(IDXGIAdapter *adapter)
{
  if(adapter == NULL)
    return;

  void **vtable = *(void ***)adapter;
  if(vtable == NULL)
    return;

  const size_t getParentIndex = 6;

  AcquireSRWLockExclusive(&g_SQCAdapterGetParentLock);

  for(size_t i = 0; i < ARRAY_COUNT(g_SQCAdapterGetParentHooks); i++)
  {
    if(g_SQCAdapterGetParentHooks[i].vtable == vtable)
    {
      ReleaseSRWLockExclusive(&g_SQCAdapterGetParentLock);
      SQCChainLog("SQC DXGI adapter GetParent hook already installed");
      return;
    }
  }

  int slot = -1;
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCAdapterGetParentHooks); i++)
  {
    if(g_SQCAdapterGetParentHooks[i].vtable == NULL)
    {
      slot = (int)i;
      break;
    }
  }

  if(slot < 0)
  {
    ReleaseSRWLockExclusive(&g_SQCAdapterGetParentLock);
    SQCChainLog("SQC DXGI adapter GetParent hook table full");
    return;
  }

  DWORD oldProtect = 0;
  if(!VirtualProtect(&vtable[getParentIndex], sizeof(void *), PAGE_READWRITE, &oldProtect))
  {
    ReleaseSRWLockExclusive(&g_SQCAdapterGetParentLock);
    SQCChainLog("SQC DXGI adapter GetParent VirtualProtect failed");
    return;
  }

  g_SQCAdapterGetParentHooks[slot].vtable = vtable;
  g_SQCAdapterGetParentHooks[slot].realGetParent =
      (SQC_IDXGIAdapter_GetParent)vtable[getParentIndex];
  vtable[getParentIndex] = (void *)&SQCAdapterGetParent_hook;

  DWORD unused = 0;
  VirtualProtect(&vtable[getParentIndex], sizeof(void *), oldProtect, &unused);
  FlushInstructionCache(GetCurrentProcess(), &vtable[getParentIndex], sizeof(void *));

  ReleaseSRWLockExclusive(&g_SQCAdapterGetParentLock);
  SQCChainLog("SQC DXGI adapter GetParent hook installed");
}

static void SQCHookRealD3D11FactoryPath(ID3D11Device *realDevice)
{
  if(realDevice == NULL)
    return;

  IDXGIDevice *dxgiDevice = NULL;
  HRESULT hr = realDevice->QueryInterface(__uuidof(IDXGIDevice), (void **)&dxgiDevice);
  if(FAILED(hr) || dxgiDevice == NULL)
  {
    SQCChainLog("SQC DXGI factory path missing IDXGIDevice");
    return;
  }

  IDXGIAdapter *adapter = NULL;
  hr = dxgiDevice->GetAdapter(&adapter);
  if(SUCCEEDED(hr) && adapter != NULL)
  {
    SQCChainLog("SQC DXGI factory path got real adapter");

    IDXGIFactory *factory = NULL;
    hr = adapter->GetParent(__uuidof(IDXGIFactory), (void **)&factory);
    if(SUCCEEDED(hr) && factory != NULL)
    {
      SQCChainLog("SQC DXGI factory path got parent factory");
      SQCHookFactorySwapchainCreates(factory);
      factory->Release();
    }
    else
    {
      SQCChainLog("SQC DXGI factory path missing parent factory");
    }

    if(SQCEnvEnabled("SQC_ENABLE_YUANSHEN_ADAPTER_GETPARENT_HOOK"))
    {
      SQCChainLog("SQC DXGI adapter GetParent vtable hook explicitly enabled");
      SQCHookAdapterGetParent(adapter);
    }
  }
  else
  {
    SQCChainLog("SQC DXGI factory path missing adapter");
  }

  SAFE_RELEASE(adapter);
  SAFE_RELEASE(dxgiDevice);
}

static IUnknown *SQCGetCOMIdentity(IUnknown *object)
{
  IUnknown *identity = NULL;
  if(object != NULL)
    object->QueryInterface(__uuidof(IUnknown), (void **)&identity);
  return identity;
}

static WrappedID3D11Device *SQCFindShadowD3D11Device(IUnknown *object)
{
  IUnknown *identity = SQCGetCOMIdentity(object);
  if(identity == NULL)
    return NULL;

  WrappedID3D11Device *wrapped = NULL;
  AcquireSRWLockShared(&g_SQCShadowD3D11Lock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCShadowD3D11Devices); i++)
  {
    if(g_SQCShadowD3D11Devices[i].identity == identity)
    {
      wrapped = g_SQCShadowD3D11Devices[i].wrapped;
      break;
    }
  }
  ReleaseSRWLockShared(&g_SQCShadowD3D11Lock);

  identity->Release();
  return wrapped;
}

static void SQCRegisterShadowD3D11Device(ID3D11Device *realDevice, WrappedID3D11Device *wrapped)
{
  IUnknown *identity = SQCGetCOMIdentity(realDevice);
  if(identity == NULL || wrapped == NULL)
  {
    SAFE_RELEASE(identity);
    return;
  }

  bool registered = false;
  bool storedIdentity = false;
  AcquireSRWLockExclusive(&g_SQCShadowD3D11Lock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCShadowD3D11Devices); i++)
  {
    if(g_SQCShadowD3D11Devices[i].identity == identity)
    {
      g_SQCShadowD3D11Devices[i].wrapped = wrapped;
      registered = true;
      break;
    }
  }

  if(!registered)
  {
    for(size_t i = 0; i < ARRAY_COUNT(g_SQCShadowD3D11Devices); i++)
    {
      if(g_SQCShadowD3D11Devices[i].identity == NULL)
      {
        g_SQCShadowD3D11Devices[i].identity = identity;
        g_SQCShadowD3D11Devices[i].wrapped = wrapped;
        registered = true;
        storedIdentity = true;
        break;
      }
    }
  }
  ReleaseSRWLockExclusive(&g_SQCShadowD3D11Lock);

  char msg[256] = {};
  wsprintfA(msg, "SQC shadow D3D11 register real=%p identity=%p wrapped=%p ok=%u", realDevice,
            identity, wrapped, registered ? 1 : 0);
  SQCChainLog(msg);

  if(!storedIdentity)
    identity->Release();
}

static bool SQCAnyShadowD3D11Device()
{
  bool found = false;
  AcquireSRWLockShared(&g_SQCShadowD3D11Lock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCShadowD3D11Devices); i++)
  {
    if(g_SQCShadowD3D11Devices[i].wrapped != NULL)
    {
      found = true;
      break;
    }
  }
  ReleaseSRWLockShared(&g_SQCShadowD3D11Lock);
  return found;
}

static WrappedID3D11Device *SQCCreateShadowD3D11Device(
    ID3D11Device *realDevice, D3D_DRIVER_TYPE DriverType, UINT Flags,
    CONST D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels, UINT SDKVersion)
{
  if(realDevice == NULL)
    return NULL;

  WrappedID3D11Device *existing = SQCFindShadowD3D11Device(realDevice);
  if(existing != NULL)
  {
    SQCChainLog("SQC shadow D3D11 reuse existing wrapper");
    return existing;
  }

  D3D11InitParams params;
  params.DriverType = DriverType;
  params.Flags = Flags;
  params.SDKVersion = SDKVersion;
  params.NumFeatureLevels = FeatureLevels;
  if(FeatureLevels > 0 && pFeatureLevels != NULL)
    memcpy(params.FeatureLevels, pFeatureLevels, sizeof(D3D_FEATURE_LEVEL) * FeatureLevels);

  realDevice->AddRef();
  WrappedID3D11Device *wrapped = new WrappedID3D11Device(realDevice, params);
  SQCRegisterShadowD3D11Device(realDevice, wrapped);
  SQCChainLog("SQC DXGI direct factory path enabled");
  SQCHookRealD3D11FactoryPath(realDevice);
  SQCHookPendingFactories();
  SQCChainLog("SQC shadow D3D11 wrapper created");
  return wrapped;
}

static void *SQCFindSwapchainCreateReal(void **vtable, size_t slot)
{
  void *real = NULL;
  AcquireSRWLockShared(&g_SQCSwapchainCreateLock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCSwapchainCreateHooks); i++)
  {
    if(g_SQCSwapchainCreateHooks[i].vtable == vtable &&
       g_SQCSwapchainCreateHooks[i].slot == slot)
    {
      real = g_SQCSwapchainCreateHooks[i].real;
      break;
    }
  }
  ReleaseSRWLockShared(&g_SQCSwapchainCreateLock);
  return real;
}

static bool SQCInstallSwapchainCreateHook(IUnknown *factory, size_t slot, void *hook,
                                          const char *name)
{
  if(factory == NULL || hook == NULL)
    return false;

  void **vtable = *(void ***)factory;
  if(vtable == NULL)
    return false;

  AcquireSRWLockExclusive(&g_SQCSwapchainCreateLock);

  for(size_t i = 0; i < ARRAY_COUNT(g_SQCSwapchainCreateHooks); i++)
  {
    if(g_SQCSwapchainCreateHooks[i].vtable == vtable &&
       g_SQCSwapchainCreateHooks[i].slot == slot)
    {
      ReleaseSRWLockExclusive(&g_SQCSwapchainCreateLock);
      char msg[160] = {};
      wsprintfA(msg, "SQC swapchain hook already installed %s slot=%u", name, (unsigned int)slot);
      SQCChainLog(msg);
      return true;
    }
  }

  int freeSlot = -1;
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCSwapchainCreateHooks); i++)
  {
    if(g_SQCSwapchainCreateHooks[i].vtable == NULL)
    {
      freeSlot = (int)i;
      break;
    }
  }

  if(freeSlot < 0)
  {
    ReleaseSRWLockExclusive(&g_SQCSwapchainCreateLock);
    SQCChainLog("SQC swapchain hook table full");
    return false;
  }

  DWORD oldProtect = 0;
  if(!VirtualProtect(&vtable[slot], sizeof(void *), PAGE_READWRITE, &oldProtect))
  {
    ReleaseSRWLockExclusive(&g_SQCSwapchainCreateLock);
    char msg[192] = {};
    wsprintfA(msg, "SQC swapchain hook VirtualProtect failed %s slot=%u err=%u", name,
              (unsigned int)slot, GetLastError());
    SQCChainLog(msg);
    return false;
  }

  g_SQCSwapchainCreateHooks[freeSlot].vtable = vtable;
  g_SQCSwapchainCreateHooks[freeSlot].slot = slot;
  g_SQCSwapchainCreateHooks[freeSlot].real = vtable[slot];
  vtable[slot] = hook;

  DWORD unused = 0;
  VirtualProtect(&vtable[slot], sizeof(void *), oldProtect, &unused);
  FlushInstructionCache(GetCurrentProcess(), &vtable[slot], sizeof(void *));

  ReleaseSRWLockExclusive(&g_SQCSwapchainCreateLock);

  char msg[224] = {};
  wsprintfA(msg, "SQC swapchain hook installed %s vtable=%p slot=%u real=%p hook=%p", name,
            vtable, (unsigned int)slot, g_SQCSwapchainCreateHooks[freeSlot].real, hook);
  SQCChainLog(msg);
  return true;
}

static HRESULT STDMETHODCALLTYPE SQC_CreateSwapChain_hook(IDXGIFactory *factory, IUnknown *device,
                                                          DXGI_SWAP_CHAIN_DESC *desc,
                                                          IDXGISwapChain **swapchain)
{
  SQCChainLog("SQC CreateSwapChain hook hit");

  SQC_IDXGIFactory_CreateSwapChain real =
      (SQC_IDXGIFactory_CreateSwapChain)SQCFindSwapchainCreateReal(*(void ***)factory, 10);
  if(real == NULL)
  {
    SQCChainLog("SQC CreateSwapChain missing real target");
    return E_FAIL;
  }

  HRESULT ret = real(factory, device, desc, swapchain);
  if(SUCCEEDED(ret) && swapchain != NULL && *swapchain != NULL)
  {
    ID3DDevice *wrapDevice = GetD3D11DeviceIfAlloc(device);
    if(wrapDevice != NULL)
    {
      if(!SQCSwapchainReturnWrapperEnabled())
      {
        HWND wnd = desc != NULL ? desc->OutputWindow : NULL;
        SQCRegisterPassthroughSwapchainWindow(wrapDevice, wnd, *swapchain, "CreateSwapChain");
        SQCChainLog("SQC CreateSwapChain passthrough real swapchain for yuanshen direct");
        return ret;
      }

      HWND wnd = desc != NULL ? desc->OutputWindow : NULL;
      *swapchain = new WrappedIDXGISwapChain4(*swapchain, wnd, wrapDevice);
      SQCChainLog("SQC CreateSwapChain wrapped swapchain");
    }
    else
    {
      SQCChainLog("SQC CreateSwapChain no D3D11 shadow device");
    }
  }

  return ret;
}

static HRESULT STDMETHODCALLTYPE SQC_CreateSwapChainForHwnd_hook(
    IDXGIFactory2 *factory, IUnknown *device, HWND hwnd, const DXGI_SWAP_CHAIN_DESC1 *desc,
    const DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreenDesc, IDXGIOutput *restrictToOutput,
    IDXGISwapChain1 **swapchain)
{
  SQCChainLog("SQC CreateSwapChainForHwnd hook hit");

  SQC_IDXGIFactory2_CreateSwapChainForHwnd real =
      (SQC_IDXGIFactory2_CreateSwapChainForHwnd)SQCFindSwapchainCreateReal(*(void ***)factory, 15);
  if(real == NULL)
  {
    SQCChainLog("SQC CreateSwapChainForHwnd missing real target");
    return E_FAIL;
  }

  HRESULT ret = real(factory, device, hwnd, desc, fullscreenDesc, restrictToOutput, swapchain);
  if(SUCCEEDED(ret) && swapchain != NULL && *swapchain != NULL)
  {
    ID3DDevice *wrapDevice = GetD3D11DeviceIfAlloc(device);
    if(wrapDevice != NULL)
    {
      if(!SQCSwapchainReturnWrapperEnabled())
      {
        SQCRegisterPassthroughSwapchainWindow(wrapDevice, hwnd, *swapchain,
                                              "CreateSwapChainForHwnd");
        SQCChainLog("SQC CreateSwapChainForHwnd passthrough real swapchain for yuanshen direct");
        return ret;
      }

      *swapchain = (IDXGISwapChain1 *)new WrappedIDXGISwapChain4(*swapchain, hwnd, wrapDevice);
      SQCChainLog("SQC CreateSwapChainForHwnd wrapped swapchain");
    }
    else
    {
      SQCChainLog("SQC CreateSwapChainForHwnd no D3D11 shadow device");
    }
  }

  return ret;
}

static HRESULT STDMETHODCALLTYPE SQC_CreateSwapChainForCoreWindow_hook(
    IDXGIFactory2 *factory, IUnknown *device, IUnknown *window, const DXGI_SWAP_CHAIN_DESC1 *desc,
    IDXGIOutput *restrictToOutput, IDXGISwapChain1 **swapchain)
{
  SQCChainLog("SQC CreateSwapChainForCoreWindow hook hit");

  SQC_IDXGIFactory2_CreateSwapChainForCoreWindow real =
      (SQC_IDXGIFactory2_CreateSwapChainForCoreWindow)SQCFindSwapchainCreateReal(
          *(void ***)factory, 16);
  if(real == NULL)
  {
    SQCChainLog("SQC CreateSwapChainForCoreWindow missing real target");
    return E_FAIL;
  }

  HRESULT ret = real(factory, device, window, desc, restrictToOutput, swapchain);
  if(SUCCEEDED(ret) && swapchain != NULL && *swapchain != NULL)
  {
    ID3DDevice *wrapDevice = GetD3D11DeviceIfAlloc(device);
    if(wrapDevice != NULL)
    {
      if(!SQCSwapchainReturnWrapperEnabled())
      {
        HWND wnd = NULL;
        (*swapchain)->GetHwnd(&wnd);
        if(wnd == NULL)
          wnd = (HWND)window;
        SQCRegisterPassthroughSwapchainWindow(wrapDevice, wnd, *swapchain,
                                              "CreateSwapChainForCoreWindow");
        SQCChainLog(
            "SQC CreateSwapChainForCoreWindow passthrough real swapchain for yuanshen direct");
        return ret;
      }

      HWND wnd = NULL;
      (*swapchain)->GetHwnd(&wnd);
      if(wnd == NULL)
        wnd = (HWND)window;
      *swapchain = (IDXGISwapChain1 *)new WrappedIDXGISwapChain4(*swapchain, wnd, wrapDevice);
      SQCChainLog("SQC CreateSwapChainForCoreWindow wrapped swapchain");
    }
    else
    {
      SQCChainLog("SQC CreateSwapChainForCoreWindow no D3D11 shadow device");
    }
  }

  return ret;
}

static HRESULT STDMETHODCALLTYPE SQC_CreateSwapChainForComposition_hook(
    IDXGIFactory2 *factory, IUnknown *device, const DXGI_SWAP_CHAIN_DESC1 *desc,
    IDXGIOutput *restrictToOutput, IDXGISwapChain1 **swapchain)
{
  SQCChainLog("SQC CreateSwapChainForComposition hook hit");

  SQC_IDXGIFactory2_CreateSwapChainForComposition real =
      (SQC_IDXGIFactory2_CreateSwapChainForComposition)SQCFindSwapchainCreateReal(
          *(void ***)factory, 24);
  if(real == NULL)
  {
    SQCChainLog("SQC CreateSwapChainForComposition missing real target");
    return E_FAIL;
  }

  HRESULT ret = real(factory, device, desc, restrictToOutput, swapchain);
  if(SUCCEEDED(ret) && swapchain != NULL && *swapchain != NULL)
  {
    ID3DDevice *wrapDevice = GetD3D11DeviceIfAlloc(device);
    if(wrapDevice != NULL)
    {
      if(!SQCSwapchainReturnWrapperEnabled())
      {
        HWND wnd = NULL;
        (*swapchain)->GetHwnd(&wnd);
        SQCRegisterPassthroughSwapchainWindow(wrapDevice, wnd, *swapchain,
                                              "CreateSwapChainForComposition");
        SQCChainLog(
            "SQC CreateSwapChainForComposition passthrough real swapchain for yuanshen direct");
        return ret;
      }

      HWND wnd = NULL;
      (*swapchain)->GetHwnd(&wnd);
      if(wnd == NULL)
        wnd = (HWND)0x1;
      *swapchain = (IDXGISwapChain1 *)new WrappedIDXGISwapChain4(*swapchain, wnd, wrapDevice);
      SQCChainLog("SQC CreateSwapChainForComposition wrapped swapchain");
    }
    else
    {
      SQCChainLog("SQC CreateSwapChainForComposition no D3D11 shadow device");
    }
  }

  return ret;
}

static void SQCHookFactorySwapchainCreates(IUnknown *factory)
{
  if(factory == NULL)
    return;

  IDXGIFactory *factory0 = NULL;
  if(SUCCEEDED(factory->QueryInterface(__uuidof(IDXGIFactory), (void **)&factory0)) &&
     factory0 != NULL)
  {
    SQCInstallSwapchainCreateHook(factory0, 10, (void *)&SQC_CreateSwapChain_hook,
                                  "CreateSwapChain");
    factory0->Release();
  }

  IDXGIFactory2 *factory2 = NULL;
  if(SUCCEEDED(factory->QueryInterface(__uuidof(IDXGIFactory2), (void **)&factory2)) &&
     factory2 != NULL)
  {
    SQCInstallSwapchainCreateHook(factory2, 15, (void *)&SQC_CreateSwapChainForHwnd_hook,
                                  "CreateSwapChainForHwnd");
    SQCInstallSwapchainCreateHook(factory2, 16, (void *)&SQC_CreateSwapChainForCoreWindow_hook,
                                  "CreateSwapChainForCoreWindow");
    SQCInstallSwapchainCreateHook(factory2, 24, (void *)&SQC_CreateSwapChainForComposition_hook,
                                  "CreateSwapChainForComposition");
    factory2->Release();
  }
}

static bool SQCQueuePendingFactory(IUnknown *factory)
{
  if(factory == NULL)
    return false;

  IUnknown *identity = SQCGetCOMIdentity(factory);
  if(identity == NULL)
    return false;

  bool queued = false;
  bool keepRef = false;
  AcquireSRWLockExclusive(&g_SQCPendingFactoryLock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCPendingFactories); i++)
  {
    if(g_SQCPendingFactories[i] == identity)
    {
      queued = true;
      break;
    }
  }

  if(!queued)
  {
    for(size_t i = 0; i < ARRAY_COUNT(g_SQCPendingFactories); i++)
    {
      if(g_SQCPendingFactories[i] == NULL)
      {
        g_SQCPendingFactories[i] = identity;
        queued = true;
        keepRef = true;
        break;
      }
    }
  }
  ReleaseSRWLockExclusive(&g_SQCPendingFactoryLock);

  char msg[160] = {};
  wsprintfA(msg, "SQC pending factory queue ok=%u factory=%p identity=%p", queued ? 1 : 0,
            factory, identity);
  SQCChainLog(msg);

  if(!keepRef)
    identity->Release();

  return queued;
}

static void SQCHookPendingFactories()
{
  IUnknown *pending[ARRAY_COUNT(g_SQCPendingFactories)] = {};

  AcquireSRWLockExclusive(&g_SQCPendingFactoryLock);
  for(size_t i = 0; i < ARRAY_COUNT(g_SQCPendingFactories); i++)
  {
    pending[i] = g_SQCPendingFactories[i];
    g_SQCPendingFactories[i] = NULL;
  }
  ReleaseSRWLockExclusive(&g_SQCPendingFactoryLock);

  for(size_t i = 0; i < ARRAY_COUNT(pending); i++)
  {
    if(pending[i] == NULL)
      continue;

    SQCChainLog("SQC installing deferred factory swapchain hook");
    SQCHookFactorySwapchainCreates(pending[i]);
    pending[i]->Release();
  }
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

  WrappedID3D11Device *shadow = SQCFindShadowD3D11Device(dev);
  if(shadow != NULL)
  {
    SQCChainLog("GetD3D11DeviceIfAlloc shadow hit");
    return shadow;
  }

  return NULL;
}

class D3D11Hook : LibraryHook
{
public:
  D3D11Hook() : LibraryHook(LibraryHook::Type::D3D11) {}

  void RegisterHooks()
  {
    InterlockedExchange(&SQC_D3D11HooksRegistered, 0);
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
    InterlockedExchange(&SQC_D3D11HooksRegistered, 1);
  }

  static PFN_D3D11_CREATE_DEVICE GetCreateDeviceOriginal()
  {
    return d3d11hooks.CreateDevice();
  }

  static PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN GetCreateDeviceAndSwapChainOriginal()
  {
    return d3d11hooks.CreateDeviceAndSwapChain();
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
    ID3D11DeviceContext *realImmediateContext = NULL;
    ID3D11DeviceContext **realImmediateContextPtr =
        ppImmediateContext != NULL ? &realImmediateContext : NULL;
    {
      ScopedSuppressHooking suppress;
      ret = real(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
                 pUsedSwapDesc, ppSwapChain, ppDevice, pFeatureLevel, realImmediateContextPtr);
    }
    {
      char msg[256] = {};
      wsprintfA(msg, "D3D11 after real CreateDevice hr=0x%08X device=%p ctx=%p swapchain=%p",
                (unsigned int)ret, ppDevice ? *ppDevice : NULL,
                realImmediateContext, ppSwapChain ? *ppSwapChain : NULL);
      SQCChainLog(msg);
    }

    SAFE_RELEASE(dummydev);
    if(dummyUsed)
      ppDevice = NULL;

    RDCDEBUG("Called real createdevice...");

    bool suppress = false;

    suppress = (Flags & D3D11_CREATE_DEVICE_PREVENT_ALTERING_LAYER_SETTINGS_FROM_REGISTRY) != 0;

    if(suppress && SQCIsYuanShenProcess() &&
       SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD"))
    {
      SQCChainLog("D3D11 yuanshen direct mode overriding PREVENT flag for full wrapping");
      suppress = false;
    }
    else if(suppress && SQCEnvEnabled("SQC_FORCE_D3D11_HOOK") && !SQCIsYuanShenProcess())
    {
      SQCChainLog("D3D11 force hook despite PREVENT_ALTERING_LAYER_SETTINGS flag");
      suppress = false;
    }
    else if(suppress && SQCEnvEnabled("SQC_FORCE_D3D11_HOOK"))
    {
      SQCChainLog("D3D11 ignore force hook for yuanshen PREVENT flag");
    }

    const bool noWrap = SQCEnvEnabled("SQC_D3D11_NO_WRAP");
    const bool yuanShenShadowPassthrough =
        SQCIsYuanShenProcess() && !SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD");

    if(suppress || noWrap || yuanShenShadowPassthrough)
    {
      if(suppress)
        RDCLOG("Application requested not to be hooked.");
      if(noWrap)
        SQCChainLog("D3D11 no-wrap diagnostic passthrough");
      if(yuanShenShadowPassthrough)
      {
        if(SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD"))
          SQCChainLog("D3D11 yuanshen direct shadow passthrough");
        else
          SQCChainLog("D3D11 yuanshen shadow passthrough");
      }

      if((suppress || yuanShenShadowPassthrough) && SUCCEEDED(ret) && ppDevice != NULL &&
         *ppDevice != NULL)
      {
        SQCChainLog("D3D11 passthrough creating shadow wrapper");
        SQCCreateShadowD3D11Device(*ppDevice, DriverType, Flags, pFeatureLevels, FeatureLevels,
                                   SDKVersion);
      }

      if(SUCCEEDED(ret) && ppImmediateContext != NULL)
      {
        *ppImmediateContext = realImmediateContext;
        realImmediateContext = NULL;
      }
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

    SAFE_RELEASE(realImmediateContext);

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
    static thread_local bool hookRecurse = false;
    SQCChainLog("D3D11CreateDevice_hook hit");

    const bool inlineHooks = SQCUseYuanShenInlineHooks();
    PFN_D3D11_CREATE_DEVICE saved = d3d11hooks.CreateDevice();
    PFN_D3D11_CREATE_DEVICE createFunc = inlineHooks
                                             ? saved
                                             : (PFN_D3D11_CREATE_DEVICE)GetSystemD3D11Proc(
                                                   "D3D11CreateDevice");
    {
      char msg[256] = {};
      wsprintfA(msg, "D3D11CreateDevice saved=%p system=%p", saved, createFunc);
      SQCChainLog(msg);
    }

    if(inlineHooks && s_SQCD3D11InlineCall)
    {
      if(saved == NULL || saved == &D3D11CreateDevice_hook)
        return E_FAIL;

      ScopedSuppressHooking suppress;
      return saved(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
                   ppDevice, pFeatureLevel, ppImmediateContext);
    }

    if(createFunc == NULL || createFunc == &D3D11CreateDevice_hook ||
       IsOwnModuleProc((FARPROC)createFunc))
    {
      RDCWARN("Call to D3D11CreateDevice_hook without valid system export");
      SQCChainLog("D3D11CreateDevice system export invalid, trying saved onward");
      createFunc = saved;
    }

    if(createFunc == NULL || createFunc == &D3D11CreateDevice_hook ||
       IsOwnModuleProc((FARPROC)createFunc))
    {
      RDCERR("Something went seriously wrong with the D3D11CreateDevice hook!");
      SQCChainLog("D3D11CreateDevice no valid real target");
      return E_UNEXPECTED;
    }

    if(SQCEnvEnabled("SQC_D3D11_RAW_PASSTHROUGH"))
    {
      SQCChainLog("D3D11CreateDevice raw passthrough begin");
      HRESULT ret = E_FAIL;
      {
        ScopedSuppressHooking suppress;
        SQCScopedD3D11InlineCall inlineCall(inlineHooks);
        ret = createFunc(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                         SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
      }

      char msg[256] = {};
      wsprintfA(msg, "D3D11CreateDevice raw passthrough end hr=0x%08X device=%p ctx=%p",
                (unsigned int)ret, ppDevice ? *ppDevice : NULL,
                ppImmediateContext ? *ppImmediateContext : NULL);
      SQCChainLog(msg);
      return ret;
    }

    if(hookRecurse)
    {
      SQCChainLog("D3D11CreateDevice recursion raw passthrough");
      ScopedSuppressHooking suppress;
      return createFunc(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                        SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
    }

    RealD3D11CreateFunction realDevice =
        [createFunc](IDXGIAdapter *adapter, D3D_DRIVER_TYPE driverType, HMODULE software,
                     UINT flags, CONST D3D_FEATURE_LEVEL *featureLevels, UINT featureLevelCount,
                     UINT sdkVersion, CONST DXGI_SWAP_CHAIN_DESC *, IDXGISwapChain **,
                     ID3D11Device **device, D3D_FEATURE_LEVEL *featureLevel,
                     ID3D11DeviceContext **context) -> HRESULT {
      return createFunc(adapter, driverType, software, flags, featureLevels, featureLevelCount,
                        sdkVersion, device, featureLevel, context);
    };

    hookRecurse = true;
    SQCScopedD3D11InlineCall inlineCall(inlineHooks);
    HRESULT ret = d3d11hooks.Create_Internal(
        realDevice, pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
        NULL, NULL, ppDevice, pFeatureLevel, ppImmediateContext);
    hookRecurse = false;
    return ret;
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

    const bool inlineHooks = SQCUseYuanShenInlineHooks();
    PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN saved = d3d11hooks.CreateDeviceAndSwapChain();

    if(inlineHooks && s_SQCD3D11InlineCall)
    {
      if(saved == NULL || saved == &D3D11CreateDeviceAndSwapChain_hook)
        return E_FAIL;

      ScopedSuppressHooking suppress;
      return saved(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
                   pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
    }

    if(hookRecurse)
    {
      SQCChainLog("D3D11CreateDeviceAndSwapChain recursion raw passthrough");
      PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN real =
          inlineHooks ? saved
                      : (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)GetSystemD3D11Proc(
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

    PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN createFunc =
        inlineHooks ? saved
                    : (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)GetSystemD3D11Proc(
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

    if(SQCEnvEnabled("SQC_D3D11_RAW_PASSTHROUGH"))
    {
      SQCChainLog("D3D11CreateDeviceAndSwapChain raw passthrough begin");
      HRESULT ret = E_FAIL;
      {
        ScopedSuppressHooking suppress;
        SQCScopedD3D11InlineCall inlineCall(inlineHooks);
        ret = createFunc(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                         SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel,
                         ppImmediateContext);
      }

      char msg[256] = {};
      wsprintfA(msg,
                "D3D11CreateDeviceAndSwapChain raw passthrough end hr=0x%08X device=%p ctx=%p "
                "swapchain=%p",
                (unsigned int)ret, ppDevice ? *ppDevice : NULL,
                ppImmediateContext ? *ppImmediateContext : NULL,
                ppSwapChain ? *ppSwapChain : NULL);
      SQCChainLog(msg);
      return ret;
    }

    hookRecurse = true;
    SQCScopedD3D11InlineCall inlineCall(inlineHooks);
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

extern "C" __declspec(dllexport) HRESULT WINAPI INTERNAL_D3D11CreateDevice(
    IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
    CONST D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    ID3D11Device **ppDevice, D3D_FEATURE_LEVEL *pFeatureLevel,
    ID3D11DeviceContext **ppImmediateContext)
{
  SQCChainLog("INTERNAL_D3D11CreateDevice bridge hit");

  PFN_D3D11_CREATE_DEVICE createFunc =
      SQCUseYuanShenInlineHooks()
          ? D3D11Hook::GetCreateDeviceOriginal()
          : (PFN_D3D11_CREATE_DEVICE)GetSystemD3D11Proc("D3D11CreateDevice");
  if(createFunc == NULL || IsOwnModuleProc((FARPROC)createFunc))
  {
    SQCChainLog("INTERNAL_D3D11CreateDevice no valid real target");
    return E_UNEXPECTED;
  }

  RealD3D11CreateFunction realDevice =
      [createFunc](IDXGIAdapter *adapter, D3D_DRIVER_TYPE driverType, HMODULE software, UINT flags,
                   CONST D3D_FEATURE_LEVEL *featureLevels, UINT featureLevelCount,
                   UINT sdkVersion, CONST DXGI_SWAP_CHAIN_DESC *, IDXGISwapChain **,
                   ID3D11Device **device, D3D_FEATURE_LEVEL *featureLevel,
                   ID3D11DeviceContext **context) -> HRESULT {
    return createFunc(adapter, driverType, software, flags, featureLevels, featureLevelCount,
                      sdkVersion, device, featureLevel, context);
  };

  return CreateD3D11_Internal(realDevice, pAdapter, DriverType, Software, Flags, pFeatureLevels,
                              FeatureLevels, SDKVersion, NULL, NULL, ppDevice, pFeatureLevel,
                              ppImmediateContext);
}

extern "C" __declspec(dllexport) HRESULT WINAPI INTERNAL_D3D11CreateDeviceAndSwapChain(
    IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
    CONST D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
    CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc, IDXGISwapChain **ppSwapChain,
    ID3D11Device **ppDevice, D3D_FEATURE_LEVEL *pFeatureLevel,
    ID3D11DeviceContext **ppImmediateContext)
{
  SQCChainLog("INTERNAL_D3D11CreateDeviceAndSwapChain bridge hit");

  PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN createFunc =
      SQCUseYuanShenInlineHooks()
          ? D3D11Hook::GetCreateDeviceAndSwapChainOriginal()
          : (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)GetSystemD3D11Proc(
                "D3D11CreateDeviceAndSwapChain");
  if(createFunc == NULL || IsOwnModuleProc((FARPROC)createFunc))
  {
    SQCChainLog("INTERNAL_D3D11CreateDeviceAndSwapChain no valid real target");
    return E_UNEXPECTED;
  }

  return CreateD3D11_Internal(createFunc, pAdapter, DriverType, Software, Flags, pFeatureLevels,
                              FeatureLevels, SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice,
                              pFeatureLevel, ppImmediateContext);
}

extern "C" __declspec(dllexport) HRESULT WINAPI INTERNAL_D3D11WrapCreatedDevice(
    D3D_DRIVER_TYPE DriverType, UINT Flags, CONST D3D_FEATURE_LEVEL *pFeatureLevels,
    UINT FeatureLevels, UINT SDKVersion, ID3D11Device **ppDevice,
    ID3D11DeviceContext **ppImmediateContext, IDXGISwapChain **ppSwapChain, HWND outputWindow)
{
  SQCChainLog("INTERNAL_D3D11WrapCreatedDevice bridge hit");

  if(ppDevice == NULL || *ppDevice == NULL)
  {
    SQCChainLog("INTERNAL_D3D11WrapCreatedDevice missing device");
    return E_INVALIDARG;
  }

  bool suppress =
      (Flags & D3D11_CREATE_DEVICE_PREVENT_ALTERING_LAYER_SETTINGS_FROM_REGISTRY) != 0;
  if(suppress && SQCIsYuanShenProcess() &&
     SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD"))
  {
    SQCChainLog("INTERNAL_D3D11WrapCreatedDevice yuanshen direct mode overriding PREVENT flag");
    suppress = false;
  }
  else if(suppress && SQCEnvEnabled("SQC_FORCE_D3D11_HOOK") && !SQCIsYuanShenProcess())
  {
    SQCChainLog("INTERNAL_D3D11WrapCreatedDevice force hook despite PREVENT flag");
    suppress = false;
  }
  else if(suppress && SQCEnvEnabled("SQC_FORCE_D3D11_HOOK"))
  {
    SQCChainLog("INTERNAL_D3D11WrapCreatedDevice ignore force hook for yuanshen PREVENT flag");
  }

  const bool noWrap = SQCEnvEnabled("SQC_D3D11_NO_WRAP");
  const bool yuanShenShadowPassthrough =
      SQCIsYuanShenProcess() && !SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD");

  if(suppress || noWrap || yuanShenShadowPassthrough)
  {
    if((suppress || yuanShenShadowPassthrough) && !noWrap)
    {
      if(yuanShenShadowPassthrough && SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD"))
        SQCChainLog("INTERNAL_D3D11WrapCreatedDevice direct passthrough shadow wrapper");
      else
        SQCChainLog("INTERNAL_D3D11WrapCreatedDevice passthrough shadow wrapper");
      SQCCreateShadowD3D11Device(*ppDevice, DriverType, Flags, pFeatureLevels, FeatureLevels,
                                 SDKVersion);
    }
    else
    {
      SQCChainLog("INTERNAL_D3D11WrapCreatedDevice passthrough");
    }
    return S_FALSE;
  }

  if(WrappedID3D11Device::IsAlloc(*ppDevice))
  {
    SQCChainLog("INTERNAL_D3D11WrapCreatedDevice already wrapped");
    return S_FALSE;
  }

  SQCChainLog("INTERNAL_D3D11WrapCreatedDevice before WrappedID3D11Device");
  D3D11InitParams params;
  params.DriverType = DriverType;
  params.Flags = Flags;
  params.SDKVersion = SDKVersion;
  params.NumFeatureLevels = FeatureLevels;
  if(FeatureLevels > 0)
    memcpy(params.FeatureLevels, pFeatureLevels, sizeof(D3D_FEATURE_LEVEL) * FeatureLevels);

  WrappedID3D11Device *wrap = new WrappedID3D11Device(*ppDevice, params);
  *ppDevice = wrap;
  SQCChainLog("INTERNAL_D3D11WrapCreatedDevice after WrappedID3D11Device");

  ID3D11DeviceContext *realImmediateContext =
      ppImmediateContext != NULL ? *ppImmediateContext : NULL;
  if(ppImmediateContext != NULL)
  {
    *ppImmediateContext = NULL;
    SQCChainLog("INTERNAL_D3D11WrapCreatedDevice before GetImmediateContext");
    wrap->GetImmediateContext(ppImmediateContext);
    SQCChainLog("INTERNAL_D3D11WrapCreatedDevice after GetImmediateContext");
  }
  SAFE_RELEASE(realImmediateContext);

  if(ppSwapChain != NULL && *ppSwapChain != NULL)
  {
    SQCChainLog("INTERNAL_D3D11WrapCreatedDevice before WrappedIDXGISwapChain4");
    *ppSwapChain = new WrappedIDXGISwapChain4(*ppSwapChain, outputWindow, wrap);
    SQCChainLog("INTERNAL_D3D11WrapCreatedDevice after WrappedIDXGISwapChain4");
  }

  return S_OK;
}

extern "C" __declspec(dllexport) HRESULT WINAPI INTERNAL_DXGIHookFactorySwapchainCreates(
    IUnknown *factory)
{
  SQCChainLog("INTERNAL_DXGIHookFactorySwapchainCreates bridge hit");
  if(factory == NULL)
  {
    SQCChainLog("INTERNAL_DXGIHookFactorySwapchainCreates missing factory");
    return E_INVALIDARG;
  }

  if(SQCAnyShadowD3D11Device())
  {
    SQCChainLog("INTERNAL_DXGIHookFactorySwapchainCreates install immediately");
    SQCHookFactorySwapchainCreates(factory);
  }
  else
  {
    SQCChainLog("INTERNAL_DXGIHookFactorySwapchainCreates defer until D3D11 shadow device");
    SQCQueuePendingFactory(factory);
  }
  return S_OK;
}
