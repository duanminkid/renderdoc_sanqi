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

// 诊断宏：写进程时序日志到 C:\sqc_steps.txt
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

static BOOL add_hooks(HMODULE hModule)
{
  wchar_t curFile[512];

  SQC_STEP("add_hooks entered");
  OutputDebugStringA("[SQC] add_hooks entered\n");

  GetModuleFileNameW(NULL, curFile, 512);

  // System processes must never be hooked. Tool processes are handled explicitly
  // by process name so target applications cannot be misclassified by inherited
  // environment variables.
  {
    wchar_t *basename = wcsrchr(curFile, L'\\');
    if(!basename) basename = wcsrchr(curFile, L'/');
    if(!basename) basename = curFile;
    else basename++;

    SQC_STEP("add_hooks basename wide check");

    if(_wcsicmp(basename, L"dllhost.exe") == 0 ||
       _wcsicmp(basename, L"explorer.exe") == 0)
    {
#if ENABLED(RDOC_RELEASE)
      OutputDebugStringA(
          "Detecting shell process! Disabling hooking in dllhost.exe or explorer.exe\n");
#endif
      SQC_STEP("excluded by basename check (system process)");
      return TRUE;
    }

    if(_wcsicmp(basename, L"qsanqiInjectTool.exe") == 0 ||
       _wcsicmp(basename, L"sanqicapture.exe") == 0 ||
       _wcsicmp(basename, L"qrenderdoc.exe") == 0 ||
       _wcsicmp(basename, L"renderdoccmd.exe") == 0)
    {
      SanQiCapture::Inst().SetReplayApp(true);
      SanQiCapture::Inst().Initialise();
      LibraryHooks::ReplayInitialise();
      SQC_STEP("tool process detected by basename, hooks skipped");
      return true;
    }
  }

  // search for an exported symbol with this name, typically system_load__replay__marker
  if(LibraryHooks::Detect(STRINGIZE(RDOC_BASE_NAME) "__replay__marker"))
  {
    RDCDEBUG("Not creating hooks - in replay app");

    SanQiCapture::Inst().SetReplayApp(true);

    SanQiCapture::Inst().Initialise();

    LibraryHooks::ReplayInitialise();

    SQC_STEP("replay marker detected, hooks skipped");
    return true;
  }

  OutputDebugStringA("[SQC] Calling Initialise\n");

  SanQiCapture::Inst().Initialise();

  SQC_STEP("after Initialise");

  RDCLOG("Loading into %ls", curFile);

  LibraryHooks::RegisterHooks();

  SQC_STEP("after RegisterHooks");

  OutputDebugStringA("[SQC] RegisterHooks done\n");

  SQC_STEP("add_hooks done");

  OutputDebugStringA("[SQC] add_hooks returning TRUE\n");

  return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  if(ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    OutputDebugStringA("[SQC] DllMain DLL_PROCESS_ATTACH\n");

    // Cache HMODULE and export addresses immediately so remote configuration
    // calls can resolve functions reliably after injection.
    CacheSelfModuleHandle();

    SQC_STEP("after CacheSelfModuleHandle");

    // add_hooks() handles process-type detection internally:
    //   - system processes (dllhost/explorer) → early return, no hooks
    //   - replay/tool processes: SetReplayApp + Initialise, no hooks
    //   - target game processes: full hooks
    BOOL ret = add_hooks(hModule);

    OutputDebugStringA("[SQC] DllMain returning\n");
    SetLastError(0);

    SQC_STEP("DllMain done");

    return ret;
  }

  return TRUE;
}
