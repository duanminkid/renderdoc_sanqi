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

// win32_libentry.cpp : Defines the entry point for the DLL
#include <tchar.h>
#include <windows.h>
#include "common/common.h"
#include "core/core.h"
#include "hooks/hooks.h"
#include "strings/string_utils.h"
#include "win32_ntquery_hook.h"
#include "win32_stealth.h"
#include "win32_vk_layer_hide.h"

static BOOL add_hooks(HMODULE hModule)
{
  wchar_t curFile[512];

// 诊断宏：写进程时序日志
#define SQC_STEP(msg)                                                                         \
  do                                                                                          \
  {                                                                                           \
    HANDLE _h = CreateFileA("C:\\sqc_steps.txt", FILE_APPEND_DATA,                           \
                            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,           \
                            FILE_ATTRIBUTE_NORMAL, NULL);                                     \
    if(_h != INVALID_HANDLE_VALUE)                                                            \
    {                                                                                         \
      char _buf[256];                                                                         \
      DWORD _w;                                                                               \
      wsprintfA(_buf, "[SQC-STEP] pid=%u " msg "\r\n", GetCurrentProcessId());               \
      WriteFile(_h, _buf, lstrlenA(_buf), &_w, NULL);                                        \
      CloseHandle(_h);                                                                        \
    }                                                                                         \
  } while(0)
  GetModuleFileNameW(NULL, curFile, 512);

  rdcstr f = get_basename(strlower(StringFormat::Wide2UTF8(curFile)));

  // bail immediately if we're in a system process. We don't want to hook, log, anything -
  // this instance is being used for a shell extension.
  if(f == "dllhost.exe" || f == "explorer.exe")
  {
#if ENABLED(RDOC_RELEASE)
    OutputDebugStringA(
        "Detecting shell process! Disabling hooking in dllhost.exe or explorer.exe\n");
#endif
    return TRUE;
  }

  // search for an exported symbol with this name, typically renderdoc__replay__marker
  if(LibraryHooks::Detect(STRINGIZE(RDOC_BASE_NAME) "__replay__marker"))
  {
    RDCDEBUG("Not creating hooks - in replay app");

    SanQiCapture::Inst().SetReplayApp(true);
    SanQiCapture::Inst().Initialise();
    LibraryHooks::ReplayInitialise();

    return true;
  }

  SanQiCapture::Inst().Initialise();

  SQC_STEP("after Initialise");

  RDCLOG("Loading into %ls", curFile);

  LibraryHooks::RegisterHooks();

  SQC_STEP("after RegisterHooks");

  // Anti-detection step 1: install NtQuery hook and Vk layer hide immediately
  InstallNtQueryHooks(hModule);

  SQC_STEP("after NtQueryHooks");

  InstallVkLayerHide();

  SQC_STEP("after VkLayerHide");

  // Anti-detection step 2: PEB unlink + PE header wipe must be deferred.
  // The injector calls FindRemoteDLL (CreateToolhelp32Snapshot) immediately after
  // LoadLibraryW returns. If we unlink too early the injector cannot find our base
  // address, causing InjectFunctionCall to fail (CaptureOptions etc. never set).
  // 300ms delay is enough for the injector to finish FindRemoteDLL + all InjectFunctionCall calls.
  struct StealthParam
  {
    HMODULE mod;
  };
  StealthParam *param = new StealthParam{hModule};

  HANDLE hThread = CreateThread(
      NULL, 0,
      [](LPVOID p) -> DWORD {
        StealthParam *sp = (StealthParam *)p;
        Sleep(300);
        // Clear env vars that expose our identity; Vulkan hook is already installed
        SetEnvironmentVariableW(L"ENABLE_VULKAN_SQC_LAYER_ACTIVATE_", NULL);
        SetEnvironmentVariableW(L"VK_INSTANCE_LAYERS", NULL);
        ApplyModuleStealth(sp->mod);
        delete sp;
        return 0;
      },
      param, 0, NULL);
  if(hThread)
    CloseHandle(hThread);

  return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  if(ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    // Cache HMODULE before PEB unlink (stealth) invalidates FROM_ADDRESS lookup
    CacheSelfModuleHandle();

    // 临时诊断：记录 DLL 基地址，方便崩溃地址转 RVA
    {
      char buf[128];
      wsprintfA(buf, "[SQC] sqclib.dll base=0x%IX\n", (uintptr_t)hModule);
      HANDLE h = CreateFileA("C:\\sqc_base.txt", FILE_APPEND_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
      if(h != INVALID_HANDLE_VALUE)
      {
        DWORD w;
        WriteFile(h, buf, lstrlenA(buf), &w, NULL);
        CloseHandle(h);
      }
    }
    BOOL ret = add_hooks(hModule);
    SetLastError(0);
    // 诊断：add_hooks完成
    {
      char _buf[128]; DWORD _w;
      HANDLE _h = CreateFileA("C:\\sqc_steps.txt", FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
      if(_h != INVALID_HANDLE_VALUE) {
        wsprintfA(_buf, "[SQC-STEP] pid=%u DllMain done ret=%d\r\n", GetCurrentProcessId(), (int)ret);
        WriteFile(_h, _buf, lstrlenA(_buf), &_w, NULL);
        CloseHandle(_h);
      }
    }
    return ret;
  }

  return TRUE;
}
