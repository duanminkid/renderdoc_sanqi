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

#include "core/core.h"
#include "hooks/hooks.h"
#include "dxgi_wrapped.h"

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

template <typename FuncType>
static FuncType SQCResolveRealDXGIExport(const char *function, void *hook)
{
  ScopedSuppressHooking suppress;

  HMODULE dxgi = GetModuleHandleA("dxgi.dll");
  if(dxgi == NULL)
    dxgi = LoadLibraryExA("dxgi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);

  FARPROC proc = dxgi ? GetProcAddress(dxgi, function) : NULL;

  char msg[512] = {};
  wsprintfA(msg, "ResolveRealDXGIExport function=%s module=%p proc=%p hook=%p", function, dxgi,
            proc, hook);
  SQCChainLog(msg);

  if(proc == NULL || proc == (FARPROC)hook)
    return NULL;

  return (FuncType)proc;
}

typedef HRESULT(WINAPI *PFN_CREATE_DXGI_FACTORY)(REFIID, void **);
typedef HRESULT(WINAPI *PFN_CREATE_DXGI_FACTORY2)(UINT, REFIID, void **);
typedef HRESULT(WINAPI *PFN_GET_DEBUG_INTERFACE)(REFIID, void **);
typedef HRESULT(WINAPI *PFN_GET_DEBUG_INTERFACE1)(UINT, REFIID, void **);

MIDL_INTERFACE("9F251514-9D4D-4902-9D60-18988AB7D4B5")
IDXGraphicsAnalysis : public IUnknown
{
  virtual void STDMETHODCALLTYPE BeginCapture() = 0;
  virtual void STDMETHODCALLTYPE EndCapture() = 0;
};

struct RenderDocAnalysis : IDXGraphicsAnalysis
{
  // IUnknown boilerplate
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { return E_NOINTERFACE; }
  ULONG STDMETHODCALLTYPE AddRef()
  {
    InterlockedIncrement(&m_iRefcount);
    return m_iRefcount;
  }
  ULONG STDMETHODCALLTYPE Release() { return InterlockedDecrement(&m_iRefcount); }
  unsigned int m_iRefcount = 0;

  // IDXGraphicsAnalysis
  void STDMETHODCALLTYPE BeginCapture()
  {
    DeviceOwnedWindow devWnd;
    SanQiCapture::Inst().GetActiveWindow(devWnd);

    SanQiCapture::Inst().StartFrameCapture(devWnd);
  }

  void STDMETHODCALLTYPE EndCapture()
  {
    DeviceOwnedWindow devWnd;
    SanQiCapture::Inst().GetActiveWindow(devWnd);

    SanQiCapture::Inst().EndFrameCapture(devWnd);
  }
};

struct DummyDXGIInfoQueue : public IDXGIInfoQueue
{
public:
  // IUnknown boilerplate
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { return E_NOINTERFACE; }
  ULONG STDMETHODCALLTYPE AddRef()
  {
    InterlockedIncrement(&m_iRefcount);
    return m_iRefcount;
  }
  ULONG STDMETHODCALLTYPE Release() { return InterlockedDecrement(&m_iRefcount); }
  unsigned int m_iRefcount = 0;
  // IDXGIInfoQueue
  virtual HRESULT STDMETHODCALLTYPE SetMessageCountLimit(DXGI_DEBUG_ID Producer,
                                                         UINT64 MessageCountLimit)
  {
    return S_OK;
  }

  virtual void STDMETHODCALLTYPE ClearStoredMessages(DXGI_DEBUG_ID Producer) { return; }
  virtual HRESULT STDMETHODCALLTYPE GetMessage(DXGI_DEBUG_ID Producer, UINT64 MessageIndex,
                                               _Out_writes_bytes_opt_(*pMessageByteLength)
                                                   DXGI_INFO_QUEUE_MESSAGE *pMessage,
                                               _Inout_ SIZE_T *pMessageByteLength)
  {
    return S_OK;
  }

  virtual UINT64 STDMETHODCALLTYPE GetNumStoredMessagesAllowedByRetrievalFilters(DXGI_DEBUG_ID Producer)
  {
    return 0;
  }

  virtual UINT64 STDMETHODCALLTYPE GetNumStoredMessages(DXGI_DEBUG_ID Producer) { return 0; }
  virtual UINT64 STDMETHODCALLTYPE GetNumMessagesDiscardedByMessageCountLimit(DXGI_DEBUG_ID Producer)
  {
    return 0;
  }

  virtual UINT64 STDMETHODCALLTYPE GetMessageCountLimit(DXGI_DEBUG_ID Producer) { return 0; }
  virtual UINT64 STDMETHODCALLTYPE GetNumMessagesAllowedByStorageFilter(DXGI_DEBUG_ID Producer)
  {
    return 0;
  }

  virtual UINT64 STDMETHODCALLTYPE GetNumMessagesDeniedByStorageFilter(DXGI_DEBUG_ID Producer)
  {
    return 0;
  }

  virtual HRESULT STDMETHODCALLTYPE AddStorageFilterEntries(DXGI_DEBUG_ID Producer,
                                                            DXGI_INFO_QUEUE_FILTER *pFilter)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE GetStorageFilter(DXGI_DEBUG_ID Producer,
                                                     _Out_writes_bytes_opt_(*pFilterByteLength)
                                                         DXGI_INFO_QUEUE_FILTER *pFilter,
                                                     _Inout_ SIZE_T *pFilterByteLength)
  {
    return S_OK;
  }

  virtual void STDMETHODCALLTYPE ClearStorageFilter(DXGI_DEBUG_ID Producer) { return; }
  virtual HRESULT STDMETHODCALLTYPE PushEmptyStorageFilter(DXGI_DEBUG_ID Producer) { return S_OK; }
  virtual HRESULT STDMETHODCALLTYPE PushDenyAllStorageFilter(DXGI_DEBUG_ID Producer)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE PushCopyOfStorageFilter(DXGI_DEBUG_ID Producer) { return S_OK; }
  virtual HRESULT STDMETHODCALLTYPE PushStorageFilter(DXGI_DEBUG_ID Producer,
                                                      DXGI_INFO_QUEUE_FILTER *pFilter)
  {
    return S_OK;
  }

  virtual void STDMETHODCALLTYPE PopStorageFilter(DXGI_DEBUG_ID Producer) { return; }
  virtual UINT STDMETHODCALLTYPE GetStorageFilterStackSize(DXGI_DEBUG_ID Producer) { return 0; }
  virtual HRESULT STDMETHODCALLTYPE AddRetrievalFilterEntries(DXGI_DEBUG_ID Producer,
                                                              DXGI_INFO_QUEUE_FILTER *pFilter)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE GetRetrievalFilter(DXGI_DEBUG_ID Producer,
                                                       _Out_writes_bytes_opt_(*pFilterByteLength)
                                                           DXGI_INFO_QUEUE_FILTER *pFilter,
                                                       _Inout_ SIZE_T *pFilterByteLength)
  {
    return S_OK;
  }

  virtual void STDMETHODCALLTYPE ClearRetrievalFilter(DXGI_DEBUG_ID Producer) { return; }
  virtual HRESULT STDMETHODCALLTYPE PushEmptyRetrievalFilter(DXGI_DEBUG_ID Producer)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE PushDenyAllRetrievalFilter(DXGI_DEBUG_ID Producer)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE PushCopyOfRetrievalFilter(DXGI_DEBUG_ID Producer)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE PushRetrievalFilter(DXGI_DEBUG_ID Producer,
                                                        DXGI_INFO_QUEUE_FILTER *pFilter)
  {
    return S_OK;
  }

  virtual void STDMETHODCALLTYPE PopRetrievalFilter(DXGI_DEBUG_ID Producer) { return; }
  virtual UINT STDMETHODCALLTYPE GetRetrievalFilterStackSize(DXGI_DEBUG_ID Producer) { return 0; }
  virtual HRESULT STDMETHODCALLTYPE AddMessage(DXGI_DEBUG_ID Producer,
                                               DXGI_INFO_QUEUE_MESSAGE_CATEGORY Category,
                                               DXGI_INFO_QUEUE_MESSAGE_SEVERITY Severity,
                                               DXGI_INFO_QUEUE_MESSAGE_ID ID, LPCSTR pDescription)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE AddApplicationMessage(DXGI_INFO_QUEUE_MESSAGE_SEVERITY Severity,
                                                          LPCSTR pDescription)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE SetBreakOnCategory(DXGI_DEBUG_ID Producer,
                                                       DXGI_INFO_QUEUE_MESSAGE_CATEGORY Category,
                                                       BOOL bEnable)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE SetBreakOnSeverity(DXGI_DEBUG_ID Producer,
                                                       DXGI_INFO_QUEUE_MESSAGE_SEVERITY Severity,
                                                       BOOL bEnable)
  {
    return S_OK;
  }

  virtual HRESULT STDMETHODCALLTYPE SetBreakOnID(DXGI_DEBUG_ID Producer,
                                                 DXGI_INFO_QUEUE_MESSAGE_ID ID, BOOL bEnable)
  {
    return S_OK;
  }

  virtual BOOL STDMETHODCALLTYPE GetBreakOnCategory(DXGI_DEBUG_ID Producer,
                                                    DXGI_INFO_QUEUE_MESSAGE_CATEGORY Category)
  {
    return FALSE;
  }

  virtual BOOL STDMETHODCALLTYPE GetBreakOnSeverity(DXGI_DEBUG_ID Producer,
                                                    DXGI_INFO_QUEUE_MESSAGE_SEVERITY Severity)
  {
    return FALSE;
  }

  virtual BOOL STDMETHODCALLTYPE GetBreakOnID(DXGI_DEBUG_ID Producer, DXGI_INFO_QUEUE_MESSAGE_ID ID)
  {
    return FALSE;
  }

  virtual void STDMETHODCALLTYPE SetMuteDebugOutput(DXGI_DEBUG_ID Producer, BOOL bMute) { return; }
  virtual BOOL STDMETHODCALLTYPE GetMuteDebugOutput(DXGI_DEBUG_ID Producer) { return FALSE; }
};

class DXGIHook : LibraryHook
{
public:
  void RegisterHooks()
  {
    SQCChainLog("DXGIHook::RegisterHooks");
    RDCLOG("Registering DXGI hooks");

    LibraryHooks::RegisterLibraryHook("dxgi.dll", NULL);

    CreateDXGIFactory.Register("dxgi.dll", "CreateDXGIFactory", CreateDXGIFactory_hook);
    CreateDXGIFactory1.Register("dxgi.dll", "CreateDXGIFactory1", CreateDXGIFactory1_hook);
    CreateDXGIFactory2.Register("dxgi.dll", "CreateDXGIFactory2", CreateDXGIFactory2_hook);
    GetDebugInterface.Register("dxgi.dll", "DXGIGetDebugInterface", DXGIGetDebugInterface_hook);
    GetDebugInterface1.Register("dxgi.dll", "DXGIGetDebugInterface1", DXGIGetDebugInterface1_hook);
  }

private:
  static DXGIHook dxgihooks;

  RenderDocAnalysis m_RenderDocAnalysis;
  DummyDXGIInfoQueue m_DummyInfoQueue;

  HookedFunction<PFN_CREATE_DXGI_FACTORY> CreateDXGIFactory;
  HookedFunction<PFN_CREATE_DXGI_FACTORY> CreateDXGIFactory1;
  HookedFunction<PFN_CREATE_DXGI_FACTORY2> CreateDXGIFactory2;
  HookedFunction<PFN_GET_DEBUG_INTERFACE> GetDebugInterface;
  HookedFunction<PFN_GET_DEBUG_INTERFACE1> GetDebugInterface1;

  static HRESULT WINAPI CreateDXGIFactory_hook(__in REFIID riid, __out void **ppFactory)
  {
    static thread_local bool inFactory = false;
    static thread_local bool inGuardFallback = false;
    SQCChainLog("CreateDXGIFactory_hook hit");
    if(ppFactory)
      *ppFactory = NULL;

    if(inFactory)
    {
      if(inGuardFallback)
      {
        SQCChainLog("CreateDXGIFactory recursion guard bounced, aborting");
        return E_FAIL;
      }

      SQCChainLog("CreateDXGIFactory recursion guard");
      PFN_CREATE_DXGI_FACTORY real = SQCResolveRealDXGIExport<PFN_CREATE_DXGI_FACTORY>(
          "CreateDXGIFactory", (void *)&CreateDXGIFactory_hook);
      if(real == NULL)
        return E_FAIL;

      ScopedSuppressHooking suppress;
      inGuardFallback = true;
      HRESULT ret = real(riid, ppFactory);
      inGuardFallback = false;
      return ret;
    }

    PFN_CREATE_DXGI_FACTORY saved = dxgihooks.CreateDXGIFactory();
    {
      char msg[256] = {};
      wsprintfA(msg, "CreateDXGIFactory saved=%p hook=%p", saved, &CreateDXGIFactory_hook);
      SQCChainLog(msg);
    }

    if(saved == (PFN_CREATE_DXGI_FACTORY)&CreateDXGIFactory_hook)
    {
      SQCChainLog("CreateDXGIFactory saved points to hook, resolving export");
      saved = SQCResolveRealDXGIExport<PFN_CREATE_DXGI_FACTORY>("CreateDXGIFactory",
                                                                (void *)&CreateDXGIFactory_hook);
      dxgihooks.CreateDXGIFactory.SetFuncPtr((void *)saved);
    }

    if(saved == NULL)
    {
      SQCChainLog("CreateDXGIFactory no valid real target");
      return E_FAIL;
    }

    SQCChainLog("CreateDXGIFactory before real");
    HRESULT ret = E_FAIL;
    {
      ScopedSuppressHooking suppress;
      inFactory = true;
      ret = saved(riid, ppFactory);
      inFactory = false;
    }
    {
      char msg[256] = {};
      wsprintfA(msg, "CreateDXGIFactory after real hr=0x%08X factory=%p", (unsigned int)ret,
                ppFactory ? *ppFactory : NULL);
      SQCChainLog(msg);
    }

    SQCChainLog("CreateDXGIFactory before HandleWrap");
    if(SUCCEEDED(ret))
      RefCountDXGIObject::HandleWrap("CreateDXGIFactory", riid, ppFactory);
    SQCChainLog("CreateDXGIFactory after HandleWrap");

    return ret;
  }

  static HRESULT WINAPI CreateDXGIFactory1_hook(__in REFIID riid, __out void **ppFactory)
  {
    static thread_local bool inFactory = false;
    static thread_local bool inGuardFallback = false;
    SQCChainLog("CreateDXGIFactory1_hook hit");
    if(ppFactory)
      *ppFactory = NULL;

    if(inFactory)
    {
      if(inGuardFallback)
      {
        SQCChainLog("CreateDXGIFactory1 recursion guard bounced, aborting");
        return E_FAIL;
      }

      SQCChainLog("CreateDXGIFactory1 recursion guard");
      PFN_CREATE_DXGI_FACTORY real = SQCResolveRealDXGIExport<PFN_CREATE_DXGI_FACTORY>(
          "CreateDXGIFactory1", (void *)&CreateDXGIFactory1_hook);
      if(real == NULL)
        return E_FAIL;

      ScopedSuppressHooking suppress;
      inGuardFallback = true;
      HRESULT ret = real(riid, ppFactory);
      inGuardFallback = false;
      return ret;
    }

    PFN_CREATE_DXGI_FACTORY saved = dxgihooks.CreateDXGIFactory1();
    {
      char msg[256] = {};
      wsprintfA(msg, "CreateDXGIFactory1 saved=%p hook=%p", saved, &CreateDXGIFactory1_hook);
      SQCChainLog(msg);
    }

    if(saved == (PFN_CREATE_DXGI_FACTORY)&CreateDXGIFactory1_hook)
    {
      SQCChainLog("CreateDXGIFactory1 saved points to hook, resolving export");
      saved = SQCResolveRealDXGIExport<PFN_CREATE_DXGI_FACTORY>("CreateDXGIFactory1",
                                                                (void *)&CreateDXGIFactory1_hook);
      dxgihooks.CreateDXGIFactory1.SetFuncPtr((void *)saved);
    }

    if(saved == NULL)
    {
      SQCChainLog("CreateDXGIFactory1 no valid real target");
      return E_FAIL;
    }

    SQCChainLog("CreateDXGIFactory1 before real");
    HRESULT ret = E_FAIL;
    {
      ScopedSuppressHooking suppress;
      inFactory = true;
      ret = saved(riid, ppFactory);
      inFactory = false;
    }
    {
      char msg[256] = {};
      wsprintfA(msg, "CreateDXGIFactory1 after real hr=0x%08X factory=%p", (unsigned int)ret,
                ppFactory ? *ppFactory : NULL);
      SQCChainLog(msg);
    }

    SQCChainLog("CreateDXGIFactory1 before HandleWrap");
    if(SUCCEEDED(ret))
      RefCountDXGIObject::HandleWrap("CreateDXGIFactory1", riid, ppFactory);
    SQCChainLog("CreateDXGIFactory1 after HandleWrap");

    return ret;
  }

  static HRESULT WINAPI CreateDXGIFactory2_hook(UINT Flags, REFIID riid, void **ppFactory)
  {
    static thread_local bool inFactory = false;
    static thread_local bool inGuardFallback = false;
    SQCChainLog("CreateDXGIFactory2_hook hit");
    if(ppFactory)
      *ppFactory = NULL;

    if(inFactory)
    {
      if(inGuardFallback)
      {
        SQCChainLog("CreateDXGIFactory2 recursion guard bounced, aborting");
        return E_FAIL;
      }

      SQCChainLog("CreateDXGIFactory2 recursion guard");
      PFN_CREATE_DXGI_FACTORY2 real = SQCResolveRealDXGIExport<PFN_CREATE_DXGI_FACTORY2>(
          "CreateDXGIFactory2", (void *)&CreateDXGIFactory2_hook);
      if(real == NULL)
        return E_FAIL;

      ScopedSuppressHooking suppress;
      inGuardFallback = true;
      HRESULT ret = real(Flags, riid, ppFactory);
      inGuardFallback = false;
      return ret;
    }

    PFN_CREATE_DXGI_FACTORY2 saved = dxgihooks.CreateDXGIFactory2();
    {
      char msg[256] = {};
      wsprintfA(msg, "CreateDXGIFactory2 saved=%p hook=%p flags=0x%X", saved,
                &CreateDXGIFactory2_hook, Flags);
      SQCChainLog(msg);
    }

    if(saved == (PFN_CREATE_DXGI_FACTORY2)&CreateDXGIFactory2_hook)
    {
      SQCChainLog("CreateDXGIFactory2 saved points to hook, resolving export");
      saved = SQCResolveRealDXGIExport<PFN_CREATE_DXGI_FACTORY2>("CreateDXGIFactory2",
                                                                 (void *)&CreateDXGIFactory2_hook);
      dxgihooks.CreateDXGIFactory2.SetFuncPtr((void *)saved);
    }

    if(saved == NULL)
    {
      SQCChainLog("CreateDXGIFactory2 no valid real target");
      return E_FAIL;
    }

    SQCChainLog("CreateDXGIFactory2 before real");
    HRESULT ret = E_FAIL;
    {
      ScopedSuppressHooking suppress;
      inFactory = true;
      ret = saved(Flags, riid, ppFactory);
      inFactory = false;
    }
    {
      char msg[256] = {};
      wsprintfA(msg, "CreateDXGIFactory2 after real hr=0x%08X factory=%p", (unsigned int)ret,
                ppFactory ? *ppFactory : NULL);
      SQCChainLog(msg);
    }

    SQCChainLog("CreateDXGIFactory2 before HandleWrap");
    if(SUCCEEDED(ret))
      RefCountDXGIObject::HandleWrap("CreateDXGIFactory2", riid, ppFactory);
    SQCChainLog("CreateDXGIFactory2 after HandleWrap");

    return ret;
  }

  static HRESULT WINAPI DXGIGetDebugInterface_hook(REFIID riid, void **ppDebug)
  {
    if(ppDebug)
      *ppDebug = NULL;

    if(riid == __uuidof(IDXGraphicsAnalysis))
    {
      dxgihooks.m_RenderDocAnalysis.AddRef();
      if(ppDebug)
        *ppDebug = &dxgihooks.m_RenderDocAnalysis;
      return S_OK;
    }
    if(riid == __uuidof(IDXGIInfoQueue))
    {
      RDCWARN(
          "Returning a dummy IDXGIInfoQueue that does nothing. SanQi Capture takes control of the "
          "debug layer.");
      dxgihooks.m_DummyInfoQueue.AddRef();
      if(ppDebug)
        *ppDebug = &dxgihooks.m_DummyInfoQueue;
      return S_OK;
    }

    // IDXGIDebug and IDXGIDebug1 can come through here, but we don't need to wrap them.

    if(dxgihooks.GetDebugInterface())
      return dxgihooks.GetDebugInterface()(riid, ppDebug);
    else
      return E_NOINTERFACE;
  }

  static HRESULT WINAPI DXGIGetDebugInterface1_hook(UINT Flags, REFIID riid, void **ppDebug)
  {
    if(ppDebug)
      *ppDebug = NULL;

    if(riid == __uuidof(IDXGraphicsAnalysis))
    {
      dxgihooks.m_RenderDocAnalysis.AddRef();
      if(ppDebug)
        *ppDebug = &dxgihooks.m_RenderDocAnalysis;
      return S_OK;
    }
    if(riid == __uuidof(IDXGIInfoQueue))
    {
      RDCWARN(
          "Returning a dummy IDXGIInfoQueue that does nothing. SanQi Capture takes control of the "
          "debug layer.");
      dxgihooks.m_DummyInfoQueue.AddRef();
      if(ppDebug)
        *ppDebug = &dxgihooks.m_DummyInfoQueue;
      return S_OK;
    }

    // IDXGIDebug and IDXGIDebug1 can come through here, but we don't need to wrap them.

    if(dxgihooks.GetDebugInterface1())
      return dxgihooks.GetDebugInterface1()(Flags, riid, ppDebug);
    else
      return E_NOINTERFACE;
  }
};

DXGIHook DXGIHook::dxgihooks;
