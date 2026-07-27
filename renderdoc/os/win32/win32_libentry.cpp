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
#include "driver/d3d11/d3d11_hooks.h"
#include "driver/dxgi/dxgi_hooks.h"
#include "hooks/hooks.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"
#include "win32_stealth.h"

static volatile LONG SQCDeferredHooksStarted = 0;
static volatile LONG SQCSteamHooksPending = 0;

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

static bool SQCEnvIsOne(const char *name)
{
  char value[16] = {};
  DWORD len = GetEnvironmentVariableA(name, value, sizeof(value));
  return len == 1 && value[0] == '1';
}

static bool SQCSteamCaptureRequested()
{
  wchar_t eventName[64] = {};
  swprintf_s(eventName, L"Local\\SQC_SteamCapture_%u", GetCurrentProcessId());
  HANDLE marker = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, eventName);
  if(marker == NULL)
    return false;

  const bool signalled = SetEvent(marker) != FALSE;
  CloseHandle(marker);
  return signalled;
}

static rdcstr SQCGetEnvVariableUTF8(const wchar_t *name)
{
  SetLastError(ERROR_SUCCESS);
  DWORD len = GetEnvironmentVariableW(name, NULL, 0);
  if(len == 0)
    return rdcstr();

  rdcarray<wchar_t> value;
  value.resize(len);
  DWORD copied = GetEnvironmentVariableW(name, value.data(), len);
  if(copied == 0 || copied >= len)
    return rdcstr();

  return StringFormat::Wide2UTF8(value.data());
}

static bool SQCValidCaptureOptions(const rdcstr &encoded)
{
  if(encoded.size() != sizeof(CaptureOptions) * 2)
    return false;

  for(char c : encoded)
    if(c < 'a' || c > 'p')
      return false;

  return true;
}

static bool SQCIsToolProcess(const rdcstr &processName)
{
  return processName.contains("injecttool.exe") || SQCEnvEnabled("SQC_TOOL_ENV");
}

static bool SQCProcessNameMatches(const wchar_t *path, const wchar_t *name)
{
  const wchar_t *base = wcsrchr(path, L'\\');
  base = base ? base + 1 : path;
  return _wcsicmp(base, name) == 0;
}

static void SQCWriteFixedTargetIdent(uint32_t ident)
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
  wsprintfA(buf, "%u", ident);
  DWORD written = 0;
  WriteFile(h, buf, (DWORD)lstrlenA(buf), &written, NULL);
  CloseHandle(h);
}

static BOOL add_hooks()
{
  wchar_t curFile[512];
  GetModuleFileNameW(NULL, curFile, 512);

  rdcstr f = get_basename(strlower(StringFormat::Wide2UTF8(curFile)));
  char msg[256] = {};
  wsprintfA(msg, "add_hooks process=%s", f.c_str());
  SQCChainLog(msg);

  const bool yuanShenDirectSystemLoad =
      f == "yuanshen.exe" && SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD");
  if(yuanShenDirectSystemLoad)
    SetEnvironmentVariableA("SQC_D3D11_DEFERRED_LIGHT_PROFILE", "1");

  const bool deferredD3D11LightProfile = SQCEnvIsOne("SQC_D3D11_DEFERRED_LIGHT_PROFILE");
  const bool d3d11InlineCaptureProfile =
      yuanShenDirectSystemLoad || deferredD3D11LightProfile;
  const bool hogwartsGameCapture =
      f == "hogwartslegacy.exe" && SQCEnvEnabled("SQC_HOGWARTS_GAME_CAPTURE");

  if(hogwartsGameCapture)
    SQCChainLog("add_hooks hogwarts D3D12/DXGI/IHV capture profile enabled");

  if(yuanShenDirectSystemLoad)
  {
    SQCChainLog("add_hooks yuanshen direct system_load mode");

    // YuanShen only needs the D3D11/DXGI capture path. Avoid the unrelated system/network hooks
    // that are incompatible with the observed startup path.
    SetEnvironmentVariableA("SQC_D3D11_LIGHT_HOOKS", "1");
    SetEnvironmentVariableA("SQC_YUANSHEN_INLINE_HOOKS", "1");
    SQCChainLog("add_hooks yuanshen D3D11/DXGI hook profile enabled");

    const rdcstr encodedOptions = SQCGetEnvVariableUTF8(L"SQC_DIRECT_CAPTURE_OPTS");
    if(!SQCValidCaptureOptions(encodedOptions))
    {
      SQCChainLog("add_hooks direct capture options missing or malformed");
      return FALSE;
    }

    CaptureOptions options;
    options.DecodeFromString(encodedOptions);
    SanQiCapture::Inst().SetCaptureOptions(options);

    const rdcstr captureFile = SQCGetEnvVariableUTF8(L"SQC_DIRECT_CAPTURE_FILE");
    if(!captureFile.empty())
      SanQiCapture::Inst().SetCaptureFileTemplate(captureFile);

    SQCChainLog("add_hooks applied direct capture config");
  }

  if(deferredD3D11LightProfile)
  {
    SetEnvironmentVariableA("SQC_D3D11_LIGHT_HOOKS", "1");
    SQCChainLog("add_hooks deferred D3D11/DXGI light profile enabled");
  }

  if(f == "yuanshen.exe" && !d3d11InlineCaptureProfile &&
     !SQCEnvEnabled("SQC_DISABLE_YUANSHEN_MINIMAL_LOAD"))
  {
    SQCWriteFixedTargetIdent(RenderDoc_FirstTargetControlPort);
    SQCChainLog("add_hooks yuanshen minimal-load diagnostic, skipping capture initialise");
    return TRUE;
  }

  if(f == "yuanshen.exe" && !d3d11InlineCaptureProfile &&
     !SQCEnvEnabled("SQC_DISABLE_YUANSHEN_CONTROL_ONLY"))
  {
    SetEnvironmentVariableA("SQC_TARGET_CONTROL_ONLY", "1");
    SQCChainLog("add_hooks yuanshen target-control-only diagnostic enabled");
  }

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

  if(SQCEnvEnabled("SQC_TARGET_CONTROL_ONLY"))
  {
    SQCChainLog("add_hooks target-control-only, skipping LibraryHooks::RegisterHooks");
    return TRUE;
  }

  RDCLOG("Loading into %ls", curFile);

  SQCChainLog("before LibraryHooks::RegisterHooks");
  LibraryHooks::RegisterHooks(d3d11InlineCaptureProfile
                                  ? LibraryHookRegistration::D3D11AndDXGI
                                  : (hogwartsGameCapture ? LibraryHookRegistration::D3D12DXGIAndIHV
                                                         : LibraryHookRegistration::All));
  SQCChainLog("after LibraryHooks::RegisterHooks");

  const bool d3d11HooksApplied =
      deferredD3D11LightProfile ? LibraryHooks::D3D11AndDXGIInlineHooksDispatchReady()
                                : LibraryHooks::HooksApplied();
  if(d3d11InlineCaptureProfile &&
     (!D3D11HooksRegistered() || !DXGIHooksRegistered() || !d3d11HooksApplied))
  {
    SQCChainLog("add_hooks D3D11/DXGI registration failed");
    return FALSE;
  }

  return TRUE;
}

static void SQCSignalHookStatus(bool succeeded)
{
  wchar_t eventName[64] = {};
  swprintf_s(eventName, succeeded ? L"Local\\SQC_HooksReady_%u" : L"Local\\SQC_HooksFailed_%u",
             GetCurrentProcessId());
  HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName);
  if(event != NULL)
  {
    SetEvent(event);
    CloseHandle(event);
    SQCChainLog(succeeded ? "add_hooks signalled hooks ready"
                          : "add_hooks signalled hooks failed");
  }
  else
  {
    SQCChainLog(succeeded ? "add_hooks hooks ready event missing"
                          : "add_hooks hooks failed event missing");
  }
}

static DWORD WINAPI SQCDeferredAddHooksThread(void *)
{
  SQCChainLog("deferred add_hooks thread begin");
  wchar_t eventName[64] = {};
  swprintf_s(eventName, L"Local\\SQC_InjectComplete_%u", GetCurrentProcessId());
  HANDLE injectionCompleteEvent = OpenEventW(SYNCHRONIZE, FALSE, eventName);
  if(injectionCompleteEvent != NULL)
  {
    DWORD waitResult = WaitForSingleObject(injectionCompleteEvent, 15000);
    CloseHandle(injectionCompleteEvent);
    if(waitResult != WAIT_OBJECT_0)
    {
      SQCChainLog(waitResult == WAIT_TIMEOUT ? "deferred add_hooks injection wait timed out"
                                             : "deferred add_hooks injection wait failed");
      SQCSignalHookStatus(false);
      return 1;
    }
    SQCChainLog("deferred add_hooks injection complete");
  }
  else
  {
    // Both launch and attach coordinators create this event before loading the DLL. Continuing
    // without it can hide the module while the final remote configuration call is still running.
    SQCChainLog("deferred add_hooks injection event missing");
    SQCSignalHookStatus(false);
    return 1;
  }

  // The launch coordinator signals only after InjectDLL has returned, so the LoadLibrary thread
  // has left DllMain. Register before the primary thread resumes to avoid missing device creation.
  BOOL ret = add_hooks();

  wchar_t processPath[MAX_PATH] = {};
  GetModuleFileNameW(NULL, processPath, MAX_PATH);
  if(ret == TRUE && SQCProcessNameMatches(processPath, L"YuanShen.exe") &&
     SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD"))
  {
    // Remote capture configuration and hook startup are complete at this point. Hiding earlier
    // makes FindRemoteDLL/InjectFunctionCall fail; leaving the module visible makes YuanShen enter
    // the observed ntdll exception loop. CacheSelfModuleHandle() ran in DllMain, so our own module
    // and embedded resources remain accessible after the PEB entry and signatures are removed.
    if(ApplyModuleStealth(GetCachedSelfModuleHandle()))
    {
      SQCChainLog("deferred add_hooks applied module stealth");
    }
    else
    {
      SQCChainLog("deferred add_hooks module stealth failed");
      ret = FALSE;
    }
  }

  SQCSignalHookStatus(ret == TRUE);

  SQCChainLog(ret ? "deferred add_hooks thread end ok" : "deferred add_hooks thread end failed");
  return ret ? 0 : 1;
}

static BOOL SQCStartDeferredAddHooks()
{
  if(InterlockedCompareExchange(&SQCDeferredHooksStarted, 1, 0) != 0)
  {
    SQCChainLog("deferred add_hooks already started");
    return TRUE;
  }

  HANDLE thread = CreateThread(NULL, 0, SQCDeferredAddHooksThread, NULL, 0, NULL);
  if(thread == NULL)
  {
    InterlockedExchange(&SQCDeferredHooksStarted, 0);
    SQCChainLog("deferred add_hooks thread create failed");
    SQCSignalHookStatus(false);
    return FALSE;
  }

  CloseHandle(thread);
  return TRUE;
}

extern "C" __declspec(dllexport) DWORD WINAPI
INTERNAL_StartYuanShenDirectHooks(const char *encodedOptions)
{
  wchar_t processPath[MAX_PATH] = {};
  GetModuleFileNameW(NULL, processPath, MAX_PATH);
  if(!SQCProcessNameMatches(processPath, L"YuanShen.exe") || encodedOptions == NULL ||
     !SQCValidCaptureOptions(encodedOptions))
  {
    SQCChainLog("remote direct hook start rejected invalid process or options");
    SQCSignalHookStatus(false);
    return 0;
  }

  SetEnvironmentVariableA("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD", "1");
  SetEnvironmentVariableA("SQC_D3D11_DEFERRED_LIGHT_PROFILE", "1");
  SetEnvironmentVariableA("SQC_D3D11_LIGHT_HOOKS", "1");
  SetEnvironmentVariableA("SQC_YUANSHEN_INLINE_HOOKS", "1");
  SetEnvironmentVariableA("SQC_DIRECT_CAPTURE_OPTS", encodedOptions);
  SQCChainLog("remote direct hook configuration applied");

  return SQCStartDeferredAddHooks() ? 1 : 0;
}

extern "C" __declspec(dllexport) void __cdecl INTERNAL_StartSteamHooks(uint32_t *succeeded)
{
  if(succeeded == NULL)
    return;

  *succeeded = 0;
  if(InterlockedCompareExchange(&SQCSteamHooksPending, 2, 1) != 1)
  {
    SQCChainLog("remote Steam hook start rejected missing marker handshake");
    return;
  }

  if(!SQCEnvEnabled("SQC_STEAM_GAME_CAPTURE"))
  {
    InterlockedExchange(&SQCSteamHooksPending, -1);
    SQCChainLog("remote Steam hook start rejected missing capture profile");
    return;
  }

  const BOOL hooksStarted = add_hooks();
  if(hooksStarted == TRUE && LibraryHooks::HookRegistrationSucceeded())
  {
    InterlockedExchange(&SQCSteamHooksPending, 3);
    *succeeded = 1;
    SQCChainLog("remote Steam hook start completed");
  }
  else
  {
    InterlockedExchange(&SQCSteamHooksPending, -1);
    SQCChainLog("remote Steam hook start failed");
  }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  if(ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    SQCChainLog("DllMain DLL_PROCESS_ATTACH");
    wchar_t curFile[512];
    GetModuleFileNameW(NULL, curFile, 512);
    CacheSelfModuleHandle();
    SQCChainLog("after CacheSelfModuleHandle");

    if(SQCSteamCaptureRequested())
    {
      InterlockedExchange(&SQCSteamHooksPending, 1);
      SQCChainLog("DllMain deferred hooks for Steam marker");
      SetLastError(0);
      SQCChainLog("DllMain returning");
      return TRUE;
    }

    if(SQCProcessNameMatches(curFile, L"YuanShen.exe") &&
       !SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD") &&
       !SQCEnvEnabled("SQC_DISABLE_YUANSHEN_DLLMAIN_EARLY_OUT"))
    {
      SQCWriteFixedTargetIdent(RenderDoc_FirstTargetControlPort);
      SQCChainLog("DllMain yuanshen early-out diagnostic after CacheSelfModuleHandle");
      SetLastError(0);
      SQCChainLog("DllMain returning");
      return TRUE;
    }

    rdcstr processName = get_basename(strlower(StringFormat::Wide2UTF8(curFile)));

    const bool yuanShenDirect =
        processName == "yuanshen.exe" && SQCEnvEnabled("SQC_YUANSHEN_DIRECT_SYSTEM_LOAD");
    const bool deferredD3D11LightProfile = SQCEnvIsOne("SQC_D3D11_DEFERRED_LIGHT_PROFILE");
    const bool d3d11InlineCaptureProfile = yuanShenDirect || deferredD3D11LightProfile;
    if(d3d11InlineCaptureProfile)
    {
      if(yuanShenDirect)
        SQCWriteFixedTargetIdent(RenderDoc_FirstTargetControlPort);
      if(!SQCStartDeferredAddHooks())
        return FALSE;
      SQCChainLog(yuanShenDirect ? "DllMain deferred add_hooks for yuanshen direct mode"
                                 : "DllMain deferred add_hooks for D3D11 light profile");
      SetLastError(0);
      SQCChainLog("DllMain returning");
      return TRUE;
    }

    BOOL ret = add_hooks();
    SetLastError(0);
    SQCChainLog("DllMain returning");
    return ret;
  }

  return TRUE;
}
