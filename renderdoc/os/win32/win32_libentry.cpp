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

static void SQCWriteTargetIdent()
{
  char path[MAX_PATH] = {};
  GetTempPathA(MAX_PATH, path);
  strcat_s(path, MAX_PATH, "sqc_target_ident_");

  char pid[32] = {};
  wsprintfA(pid, "%u.txt", GetCurrentProcessId());
  strcat_s(path, MAX_PATH, pid);

  HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(h == INVALID_HANDLE_VALUE)
    return;

  char buf[64] = {};
  wsprintfA(buf, "%u", SanQiCapture::Inst().GetTargetControlIdent());
  DWORD written = 0;
  WriteFile(h, buf, (DWORD)lstrlenA(buf), &written, NULL);
  CloseHandle(h);
}

static bool SQCEnvEnabled(const char *name)
{
  char value[16] = {};
  DWORD len = GetEnvironmentVariableA(name, value, sizeof(value));
  return len > 0 && _stricmp(value, "0") != 0 && _stricmp(value, "false") != 0 &&
         _stricmp(value, "off") != 0;
}

static bool SQCIsToolProcess(const rdcstr &processName)
{
  return processName.contains("injecttool.exe") || SQCEnvEnabled("SQC_TOOL_ENV");
}

static BOOL add_hooks()
{
  wchar_t curFile[512];
  GetModuleFileNameW(NULL, curFile, 512);

  rdcstr f = get_basename(strlower(StringFormat::Wide2UTF8(curFile)));
  char msg[256] = {};
  wsprintfA(msg, "add_hooks process=%s", f.c_str());
  SQCChainLog(msg);

  if(SQCIsToolProcess(f))
  {
    SQCChainLog("add_hooks skip tool process");
    SanQiCapture::Inst().SetReplayApp(true);
    SanQiCapture::Inst().Initialise();
    LibraryHooks::ReplayInitialise();
    return true;
  }

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

  // search for an exported symbol with this name, typically system_load__replay__marker
  if(LibraryHooks::Detect(STRINGIZE(RDOC_BASE_NAME) "__replay__marker"))
  {
    RDCDEBUG("Not creating hooks - in replay app");

    SanQiCapture::Inst().SetReplayApp(true);

    SanQiCapture::Inst().Initialise();

    LibraryHooks::ReplayInitialise();

    return true;
  }

  SanQiCapture::Inst().Initialise();
  SQCChainLog("after SanQiCapture::Initialise");
  SQCWriteTargetIdent();

  RDCLOG("Loading into %ls", curFile);

  SQCChainLog("before LibraryHooks::RegisterHooks");
  LibraryHooks::RegisterHooks();
  SQCChainLog("after LibraryHooks::RegisterHooks");

  return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  if(ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    SQCChainLog("DllMain DLL_PROCESS_ATTACH");
    CacheSelfModuleHandle();
    SQCChainLog("after CacheSelfModuleHandle");
    BOOL ret = add_hooks();
    SetLastError(0);
    SQCChainLog("DllMain returning");
    return ret;
  }

  return TRUE;
}
