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

#include <Psapi.h>
#include <Shlwapi.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <winternl.h>
#include "api/replay/capture_options.h"
#include "common/formatting.h"
#include "core/core.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"

#include <string>

// Write diagnostic message to OutputDebugString and %TEMP%\sqc_inject_diag.txt
static void SqcDiagLog(const char *msg)
{
  OutputDebugStringA(msg);
  wchar_t tmpPath[MAX_PATH];
  GetTempPathW(MAX_PATH, tmpPath);
  wcscat_s(tmpPath, L"sqc_inject_diag.txt");
  HANDLE hf = CreateFileW(tmpPath, FILE_APPEND_DATA,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(hf != INVALID_HANDLE_VALUE)
  {
    DWORD w;
    WriteFile(hf, msg, (DWORD)lstrlenA(msg), &w, NULL);
    CloseHandle(hf);
  }
}

static uint32_t ReadProxyIdent(const rdcstr &identFile);
static uint32_t WaitForProxyIdentFile(const rdcstr &identFile, HANDLE process, DWORD timeoutMS);

static uint32_t ReadTargetIdentFile(uint32_t pid)
{
  wchar_t path[MAX_PATH] = {};
  GetTempPathW(MAX_PATH, path);
  wcscat_s(path, L"sqc_target_ident_");

  wchar_t pidbuf[32] = {};
  swprintf_s(pidbuf, L"%u.txt", pid);
  wcscat_s(path, pidbuf);

  FILE *f = FileIO::fopen(StringFormat::Wide2UTF8(path), FileIO::ReadText);
  if(f == NULL)
    return 0;

  char buf[64] = {};
  size_t read = fread(buf, 1, sizeof(buf) - 1, f);
  FileIO::fclose(f);

  if(read == 0)
    return 0;

  return (uint32_t)strtoul(buf, NULL, 10);
}

static uint32_t WaitForTargetIdentFile(uint32_t pid, HANDLE process, DWORD timeoutMS)
{
  DWORD start = GetTickCount();
  DWORD exitCode = STILL_ACTIVE;

  for(;;)
  {
    uint32_t ident = ReadTargetIdentFile(pid);
    if(ident != 0)
      return ident;

    if(process != NULL && GetExitCodeProcess(process, &exitCode) && exitCode != STILL_ACTIVE)
      return 0;

    if(GetTickCount() - start >= timeoutMS)
      return 0;

    Sleep(25);
  }
}

static void SignalInjectionComplete(uint32_t pid)
{
  wchar_t eventName[64] = {};
  swprintf_s(eventName, L"Local\\SQC_InjectComplete_%u", pid);
  HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName);
  if(event == NULL)
    return;

  SetEvent(event);
  CloseHandle(event);
  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] InjectionComplete signalled pid=%u\r\n", pid)
                 .c_str());
}

static bool IsYuanShenProcess(HANDLE process)
{
  wchar_t processPath[MAX_PATH] = {};
  DWORD processPathSize = MAX_PATH;
  if(!QueryFullProcessImageNameW(process, 0, processPath, &processPathSize))
    return false;

  const wchar_t *backslash = wcsrchr(processPath, L'\\');
  const wchar_t *slash = wcsrchr(processPath, L'/');
  const wchar_t *base = backslash;
  if(slash != NULL && (base == NULL || slash > base))
    base = slash;
  base = base != NULL ? base + 1 : processPath;
  return _wcsicmp(base, L"YuanShen.exe") == 0;
}

// NtCreateThreadEx: undocumented NT API (kept for future use)
typedef NTSTATUS(NTAPI *PFN_NtCreateThreadEx)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                              PVOID ObjectAttributes, HANDLE ProcessHandle,
                                              PVOID StartRoutine, PVOID Argument,
                                              ULONG CreateFlags, SIZE_T ZeroBits,
                                              SIZE_T StackSize, SIZE_T MaximumStackSize,
                                              PVOID AttributeList);

static rdcarray<EnvironmentModification> &GetEnvModifications()
{
  static rdcarray<EnvironmentModification> envCallbacks;
  return envCallbacks;
}

struct InsensitiveComparison
{
  bool operator()(const rdcstr &a, const rdcstr &b) const { return strlower(a) < strlower(b); }
};

typedef std::map<rdcstr, rdcstr, InsensitiveComparison> EnvMap;

static EnvMap EnvStringToEnvMap(const wchar_t *envstring)
{
  EnvMap ret;

  const wchar_t *e = envstring;

  while(*e)
  {
    const wchar_t *equals = wcschr(e, L'=');

    rdcstr name = StringFormat::Wide2UTF8(rdcwstr(e, equals - e));
    rdcstr value = StringFormat::Wide2UTF8(equals + 1);

    ret[name] = value;

    // jump to \0 and past it
    e += wcslen(e) + 1;
  }

  return ret;
}

void Process::RegisterEnvironmentModification(const EnvironmentModification &modif)
{
  GetEnvModifications().push_back(modif);
}

static void ApplyEnvModifications(EnvMap &envValues,
                                  const rdcarray<EnvironmentModification> &modifications,
                                  bool setToSystem)
{
  for(size_t i = 0; i < modifications.size(); i++)
  {
    const EnvironmentModification &m = modifications[i];

    rdcstr value;

    auto it = envValues.find(m.name);
    if(it != envValues.end())
      value = it->second;

    switch(m.mod)
    {
      case EnvMod::Set: value = m.value.c_str(); break;
      case EnvMod::Append:
      {
        if(!value.empty())
        {
          if(m.sep == EnvSep::Platform || m.sep == EnvSep::SemiColon)
            value += ";";
          else if(m.sep == EnvSep::Colon)
            value += ":";
        }
        value += m.value.c_str();
        break;
      }
      case EnvMod::Prepend:
      {
        if(!value.empty())
        {
          rdcstr prep = m.value;
          if(m.sep == EnvSep::Platform || m.sep == EnvSep::SemiColon)
            prep += ";";
          else if(m.sep == EnvSep::Colon)
            prep += ":";
          value = prep + value;
        }
        else
        {
          value = m.value.c_str();
        }
        break;
      }
    }

    envValues[m.name] = value;

    if(setToSystem)
      SetEnvironmentVariableW(StringFormat::UTF82Wide(m.name).c_str(),
                              StringFormat::UTF82Wide(value).c_str());
  }
}

// on windows we apply environment changes here, after process initialisation
// but before any real work (in SanQi Capture::Initialise) so that we support
// injecting the dll into processes we didn't launch (ie didn't control the
// starting environment for), or even the application loading the dll itself
// without any interaction with our replay app.
void Process::ApplyEnvironmentModification()
{
  // turn environment string to a UTF-8 map
  LPWCH envStrings = GetEnvironmentStringsW();
  EnvMap envValues = EnvStringToEnvMap(envStrings);
  FreeEnvironmentStringsW(envStrings);
  rdcarray<EnvironmentModification> &modifications = GetEnvModifications();

  ApplyEnvModifications(envValues, modifications, true);

  // these have been applied to the current process
  modifications.clear();
}

rdcstr Process::GetEnvVariable(const rdcstr &name)
{
  DWORD len = GetEnvironmentVariableA(name.c_str(), NULL, 0);
  if(len == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND)
    return rdcstr();

  rdcstr ret;
  ret.resize(len + 1);

  GetEnvironmentVariableA(name.c_str(), ret.data(), len);
  ret.trim();
  return ret;
}

static bool TextMatchesProcessList(const rdcstr &text, const rdcstr &list)
{
  rdcstr lowered = strlower(text);
  rdcarray<rdcstr> entries;
  split(list, entries, ';');

  for(rdcstr entry : entries)
  {
    entry = strlower(entry.trimmed());

    if(entry.empty())
      continue;

    if(lowered.contains(entry))
      return true;
  }

  return false;
}

bool Process::IsInjectionBlockedProcessText(const rdcstr &text)
{
  static const char *defaultBlocklist =
      "sanqicapture.exe;"
      "qsanqiinjecttool.exe;"
      "steam.exe;"
      "steamwebhelper.exe;"
      "steamservice.exe;"
      "UnityCrashHandler64.exe;"
      "crashreport.exe;"
      "upload_crash.exe;"
      "APM4webCrashR.exe;"
      "ZFGameBrowser.exe;"
      "WerFault.exe";

  if(TextMatchesProcessList(text, defaultBlocklist))
    return true;

  rdcstr envBlocklist = Process::GetEnvVariable("SQC_INJECT_BLOCKLIST");
  if(!envBlocklist.empty() && TextMatchesProcessList(text, envBlocklist))
    return true;

  return false;
}

bool Process::IsInjectionBlockedProcess(uint32_t pid)
{
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if(hProcess == NULL)
    return false;

  char processName[MAX_PATH] = {};
  DWORD size = MAX_PATH;
  bool blocked = false;

  if(QueryFullProcessImageNameA(hProcess, 0, processName, &size))
    blocked = Process::IsInjectionBlockedProcessText(processName);

  CloseHandle(hProcess);
  return blocked;
}

uint64_t Process::GetMemoryUsage()
{
  HANDLE proc = GetCurrentProcess();

  if(proc == NULL)
  {
    RDCERR("Couldn't open process: %d", GetLastError());
    return 0;
  }

  PROCESS_MEMORY_COUNTERS memInfo = {};

  uint64_t ret = 0;

  if(GetProcessMemoryInfo(proc, &memInfo, sizeof(memInfo)))
  {
    ret = memInfo.WorkingSetSize;
  }
  else
  {
    RDCERR("Couldn't get process memory info: %d", GetLastError());
  }

  return ret;
}

// helpers for various shims and dlls etc, not part of the public API
extern "C" __declspec(dllexport) void __cdecl INTERNAL_GetTargetControlIdent(uint32_t *ident)
{
  if(ident)
    *ident = SanQiCapture::Inst().GetTargetControlIdent();
}

extern "C" __declspec(dllexport) void __cdecl INTERNAL_SetCaptureOptions(CaptureOptions *opts)
{
  if(opts)
    SanQiCapture::Inst().SetCaptureOptions(*opts);
}

extern "C" __declspec(dllexport) void __cdecl INTERNAL_SetCaptureFile(const char *capfile)
{
  if(capfile)
    SanQiCapture::Inst().SetCaptureFileTemplate(capfile);
}

extern "C" __declspec(dllexport) void __cdecl INTERNAL_SetDebugLogFile(const char *logfile)
{
  RENDERDOC_SetDebugLogFile(logfile ? logfile : rdcstr());
}

static EnvironmentModification tempEnvMod;

extern "C" __declspec(dllexport) void __cdecl INTERNAL_EnvModName(const char *name)
{
  if(name)
    tempEnvMod.name = name;
}

extern "C" __declspec(dllexport) void __cdecl INTERNAL_EnvModValue(const char *value)
{
  if(value)
    tempEnvMod.value = value;
}

extern "C" __declspec(dllexport) void __cdecl INTERNAL_EnvSep(EnvSep *sep)
{
  if(sep)
    tempEnvMod.sep = *sep;
}

extern "C" __declspec(dllexport) void __cdecl INTERNAL_EnvMod(EnvMod *mod)
{
  if(mod)
  {
    tempEnvMod.mod = *mod;
    Process::RegisterEnvironmentModification(tempEnvMod);
  }
}

extern "C" __declspec(dllexport) void __cdecl INTERNAL_ApplyEnvMods(void *ignored)
{
  Process::ApplyEnvironmentModification();
}

static const DWORD InjectRemoteThreadTimeoutMS = 30000;
static rdcstr InjectDLLFailure;

bool InjectDLL(HANDLE hProcess, rdcwstr libName)
{
  InjectDLLFailure.clear();

  wchar_t dllPath[MAX_PATH + 1] = {0};
  wcscpy_s(dllPath, libName.c_str());

  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] InjectDLL BEGIN: tick=%u path='%s'\r\n",
                               GetTickCount(), StringFormat::Wide2UTF8(dllPath).c_str())
                 .c_str());

  static HMODULE kernel32 = GetModuleHandleA("kernel32.dll");

  if(kernel32 == NULL)
  {
    RDCERR("Couldn't get handle for kernel32.dll");
    InjectDLLFailure = "kernel32.dll handle is null";
    SqcDiagLog("[SQC-DIAG] InjectDLL failed: kernel32 handle is null\r\n");
    return false;
  }

  FARPROC loadLibraryW = GetProcAddress(kernel32, "LoadLibraryW");
  if(loadLibraryW == NULL)
  {
    DWORD err = GetLastError();
    RDCERR("Couldn't get LoadLibraryW address: %u", err);
    InjectDLLFailure = StringFormat::Fmt("GetProcAddress(LoadLibraryW) failed with err %u", err);
    SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] InjectDLL failed: LoadLibraryW missing err=%u\r\n",
                                 err)
                   .c_str());
    return false;
  }

  bool ret = false;
  void *remoteMem =
      VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE);
  if(remoteMem)
  {
    SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] InjectDLL remote memory=%p bytes=%llu\r\n",
                                 remoteMem, (unsigned long long)sizeof(dllPath))
                   .c_str());

    BOOL success = WriteProcessMemory(hProcess, remoteMem, (void *)dllPath, sizeof(dllPath), NULL);
    if(success)
    {
      SqcDiagLog("[SQC-DIAG] InjectDLL WriteProcessMemory OK\r\n");

      HANDLE hThread = CreateRemoteThread(
          hProcess, NULL, 1024 * 1024U, (LPTHREAD_START_ROUTINE)loadLibraryW, remoteMem, 0, NULL);
      if(hThread)
      {
        SqcDiagLog("[SQC-DIAG] InjectDLL CreateRemoteThread OK\r\n");

        DWORD waitRet = WaitForSingleObject(hThread, InjectRemoteThreadTimeoutMS);
        if(waitRet != WAIT_OBJECT_0)
        {
          DWORD err = GetLastError();
          RDCERR("Timed out waiting for remote LoadLibraryW thread, wait result: %u, err: %u",
                 waitRet, err);
          InjectDLLFailure =
              StringFormat::Fmt("remote LoadLibraryW wait failed waitRet=%u err=%u", waitRet, err);
          SqcDiagLog(StringFormat::Fmt(
                         "[SQC-DIAG] InjectDLL wait failed waitRet=%u err=%u\r\n", waitRet, err)
                         .c_str());
          CloseHandle(hThread);
          return false;
        }

        DWORD threadExitCode = 0;
        GetExitCodeThread(hThread, &threadExitCode);
        CloseHandle(hThread);
        // Log LoadLibraryW result (exit code = HMODULE, 0 means failure)
        char diagBuf[256];
        wsprintfA(diagBuf, "[SQC-DIAG] InjectDLL: tick=%u LoadLibraryW exitCode(HMODULE)=0x%X err=%u\r\n",
                  GetTickCount(), threadExitCode, GetLastError());
        SqcDiagLog(diagBuf);
        ret = (threadExitCode != 0);
        if(!ret)
          InjectDLLFailure = "remote LoadLibraryW returned NULL";
      }
      else
      {
        DWORD err = GetLastError();
        RDCERR("Couldn't create remote thread for LoadLibraryW: %u", err);
        InjectDLLFailure = StringFormat::Fmt("CreateRemoteThread failed with err %u", err);
        SqcDiagLog(StringFormat::Fmt(
                       "[SQC-DIAG] InjectDLL CreateRemoteThread failed err=%u\r\n", err)
                       .c_str());
      }
    }
    else
    {
      DWORD err = GetLastError();
      RDCERR("Couldn't write remote memory %p with dllPath '%ls': %u", remoteMem, dllPath, err);
      InjectDLLFailure = StringFormat::Fmt("WriteProcessMemory failed with err %u", err);
      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] InjectDLL WriteProcessMemory failed err=%u\r\n", err)
                     .c_str());
    }

    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
  }
  else
  {
    DWORD err = GetLastError();
    RDCERR("Couldn't allocate remote memory for DLL '%ls': %u", libName.c_str(), err);
    InjectDLLFailure = StringFormat::Fmt("VirtualAllocEx failed with err %u", err);
    SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] InjectDLL VirtualAllocEx failed err=%u\r\n", err)
                   .c_str());
  }

  return ret;
}

uintptr_t FindRemoteDLL(DWORD pid, rdcstr libName)
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE;

  rdcwstr wlibName = StringFormat::UTF82Wide(strlower(libName));

  // up to 10 retries
  for(int i = 0; i < 10; i++)
  {
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

    if(hModuleSnap == INVALID_HANDLE_VALUE)
    {
      DWORD err = GetLastError();

      RDCWARN("CreateToolhelp32Snapshot(%u) -> 0x%08x", pid, err);

      // retry if error is ERROR_BAD_LENGTH
      if(err == ERROR_BAD_LENGTH)
        continue;
    }

    // didn't retry, or succeeded
    break;
  }

  if(hModuleSnap == INVALID_HANDLE_VALUE)
  {
    RDCERR("Couldn't create toolhelp dump of modules in process %u", pid);
    return 0;
  }

  MODULEENTRY32 me32;
  RDCEraseEl(me32);
  me32.dwSize = sizeof(MODULEENTRY32);

  BOOL success = Module32First(hModuleSnap, &me32);

  if(success == FALSE)
  {
    DWORD err = GetLastError();

    RDCERR("Couldn't get first module in process %u: 0x%08x", pid, err);
    CloseHandle(hModuleSnap);
    return 0;
  }

  uintptr_t ret = 0;

  int numModules = 0;

  do
  {
    wchar_t modnameLower[MAX_MODULE_NAME32 + 1];
    RDCEraseEl(modnameLower);
    wcsncpy_s(modnameLower, me32.szModule, MAX_MODULE_NAME32);

    wchar_t *wc = &modnameLower[0];
    while(*wc)
    {
      *wc = towlower(*wc);
      wc++;
    }

    numModules++;

    if(wcsstr(modnameLower, wlibName.c_str()) == modnameLower)
    {
      ret = (uintptr_t)me32.modBaseAddr;
    }
  } while(ret == 0 && Module32Next(hModuleSnap, &me32));

  if(ret == 0)
  {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    DWORD exitCode = 0;

    if(h)
      GetExitCodeProcess(h, &exitCode);

    if(h == NULL || exitCode != STILL_ACTIVE)
    {
      RDCERR(
          "Error injecting into remote process with PID %u which is no longer available.\n"
          "Possibly the process has crashed during early startup, or is missing DLLs to run?",
          pid);
    }
    else
    {
      RDCERR("Couldn't find module '%s' among %d modules", libName.c_str(), numModules);
    }

    if(h)
      CloseHandle(h);
  }

  CloseHandle(hModuleSnap);

  return ret;
}

bool InjectFunctionCall(HANDLE hProcess, uintptr_t renderdoc_remote, const char *funcName,
                        void *data, const size_t dataLen)
{
  if(dataLen == 0)
  {
    RDCERR("Invalid function call injection attempt");
    return false;
  }

  RDCDEBUG("Injecting call to %s", funcName);
  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] InjectFunctionCall BEGIN: tick=%u func=%s bytes=%llu\r\n",
                               GetTickCount(), funcName, (unsigned long long)dataLen)
                 .c_str());

  HMODULE renderdoc_local = GetModuleHandleA(STRINGIZE(RDOC_BASE_NAME) ".dll");
  if(renderdoc_local == NULL)
    renderdoc_local = GetCachedSelfModuleHandle();
  if(renderdoc_local == NULL)
  {
    RDCERR("Couldn't get local module handle for injected call to %s", funcName);
    return false;
  }

  uintptr_t func_local = (uintptr_t)GetProcAddress(renderdoc_local, funcName);
  if(func_local == 0)
  {
    RDCERR("Couldn't find local function %s for injected call", funcName);
    return false;
  }

  // we've found SetCaptureOptions in our local instance of the module, now calculate the offset and
  // so get the function
  // in the remote module (which might be loaded at a different base address
  uintptr_t func_remote = func_local + renderdoc_remote - (uintptr_t)renderdoc_local;

  void *remoteMem = VirtualAllocEx(hProcess, NULL, dataLen, MEM_COMMIT, PAGE_READWRITE);
  if(remoteMem == NULL)
  {
    RDCERR("Couldn't allocate remote memory for injected call to %s: %u", funcName, GetLastError());
    return false;
  }

  SIZE_T numWritten;
  if(!WriteProcessMemory(hProcess, remoteMem, data, dataLen, &numWritten) || numWritten != dataLen)
  {
    RDCERR("Couldn't write remote memory for injected call to %s: %u", funcName, GetLastError());
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return false;
  }

  HANDLE hThread =
      CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)func_remote, remoteMem, 0, NULL);
  if(hThread == NULL)
  {
    RDCERR("Couldn't create remote thread for injected call to %s: %u", funcName, GetLastError());
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return false;
  }

  DWORD waitRet = WaitForSingleObject(hThread, InjectRemoteThreadTimeoutMS);
  if(waitRet != WAIT_OBJECT_0)
  {
    RDCERR("Timed out waiting for injected call to %s, wait result: %u, err: %u", funcName,
           waitRet, GetLastError());
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] InjectFunctionCall TIMEOUT: tick=%u func=%s wait=%u err=%u\r\n",
                   GetTickCount(), funcName, waitRet, GetLastError())
                   .c_str());
    CloseHandle(hThread);
    return false;
  }

  if(!ReadProcessMemory(hProcess, remoteMem, data, dataLen, &numWritten) || numWritten != dataLen)
  {
    RDCERR("Couldn't read remote memory for injected call to %s: %u", funcName, GetLastError());
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return false;
  }

  CloseHandle(hThread);
  VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] InjectFunctionCall OK: tick=%u func=%s\r\n",
                               GetTickCount(), funcName)
                 .c_str());
  return true;
}

static PROCESS_INFORMATION RunProcess(const rdcstr &app, const rdcstr &workingDir,
                                      const rdcstr &cmdLine,
                                      const rdcarray<EnvironmentModification> &env, bool internal,
                                      HANDLE *phChildStdOutput_Rd, HANDLE *phChildStdError_Rd)
{
  PROCESS_INFORMATION pi;
  STARTUPINFO si;
  SECURITY_ATTRIBUTES pSec;
  SECURITY_ATTRIBUTES tSec;

  RDCEraseEl(pi);
  RDCEraseEl(si);
  RDCEraseEl(pSec);
  RDCEraseEl(tSec);

  si.cb = sizeof(si);

  pSec.nLength = sizeof(pSec);
  tSec.nLength = sizeof(tSec);

  rdcwstr workdir = L"";

  if(!workingDir.empty())
    workdir = StringFormat::UTF82Wide(workingDir);
  else
    workdir = StringFormat::UTF82Wide(get_dirname(app));

  wchar_t *paramsAlloc = NULL;

  rdcwstr wapp = StringFormat::UTF82Wide(app);

  // CreateProcessW can modify the params, need space.
  size_t len = wapp.length() + 10;

  rdcwstr wcmd = L"";

  if(!cmdLine.empty())
  {
    wcmd = StringFormat::UTF82Wide(cmdLine);
    len += wcmd.length();
  }

  paramsAlloc = new wchar_t[len];

  RDCEraseMem(paramsAlloc, len * sizeof(wchar_t));

  wcscpy_s(paramsAlloc, len, L"\"");
  wcscat_s(paramsAlloc, len, wapp.c_str());
  wcscat_s(paramsAlloc, len, L"\"");

  if(!cmdLine.empty())
  {
    wcscat_s(paramsAlloc, len, L" ");
    wcscat_s(paramsAlloc, len, wcmd.c_str());
  }

  bool inheritHandles = false;

  HANDLE hChildStdOutput_Wr = 0, hChildStdError_Wr = 0;
  if(phChildStdOutput_Rd)
  {
    RDCASSERT(phChildStdError_Rd);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if(!CreatePipe(phChildStdOutput_Rd, &hChildStdOutput_Wr, &sa, 0))
      RDCERR("Could not create pipe to read stdout");
    if(!SetHandleInformation(*phChildStdOutput_Rd, HANDLE_FLAG_INHERIT, 0))
      RDCERR("Could not set pipe handle information");

    if(!CreatePipe(phChildStdError_Rd, &hChildStdError_Wr, &sa, 0))
      RDCERR("Could not create pipe to read stdout");
    if(!SetHandleInformation(*phChildStdError_Rd, HANDLE_FLAG_INHERIT, 0))
      RDCERR("Could not set pipe handle information");

    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdOutput = hChildStdOutput_Wr;
    si.hStdError = hChildStdError_Wr;

    // Need to inherit handles in CreateProcess for ReadFile to read stdout
    inheritHandles = true;
  }

  // if it's a utility launch, hide the command prompt window from showing
  if(phChildStdOutput_Rd || internal)
    si.dwFlags |= STARTF_USESHOWWINDOW;

  if(!internal)
    RDCLOG("Running process %s", app.c_str());

  // turn environment string to a UTF-8 map
  std::wstring envString;

  if(!env.empty() || !internal)
  {
    LPWCH envStrings = GetEnvironmentStringsW();
    EnvMap envValues = EnvStringToEnvMap(envStrings);
    FreeEnvironmentStringsW(envStrings);

    if(!internal)
      envValues.erase("SQC_TOOL_ENV");

    if(!env.empty())
      ApplyEnvModifications(envValues, env, false);

    for(auto it = envValues.begin(); it != envValues.end(); ++it)
    {
      envString += StringFormat::UTF82Wide(it->first).c_str();
      envString += L"=";
      envString += StringFormat::UTF82Wide(it->second).c_str();
      envString.push_back(0);
    }

    // Environment blocks passed to CreateProcessW must be terminated by an extra NUL.
    if(!envString.empty())
      envString.push_back(0);
  }

  BOOL retValue = CreateProcessW(
      NULL, paramsAlloc, &pSec, &tSec, inheritHandles, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
      envString.empty() ? NULL : (void *)envString.data(), workdir.c_str(), &si, &pi);

  DWORD err = GetLastError();

  if(retValue && (!internal || Process::GetEnvVariable("SQC_VERBOSE_PROCESS_LOG") == "1"))
  {
    // diagnostic: log CreateProcessW success
    char diagBuf[512];
    wsprintfA(diagBuf,
              "[SQC-DIAG] RunProcess SUCCESS: tick=%u pid=%u app='%s' inputWorkDir='%s' "
              "actualWorkDir='%s'\r\n",
              GetTickCount(), pi.dwProcessId, app.c_str(), workingDir.c_str(),
              StringFormat::Wide2UTF8(workdir).c_str());
    SqcDiagLog(diagBuf);
  }

  if(phChildStdOutput_Rd)
  {
    CloseHandle(hChildStdOutput_Wr);
    CloseHandle(hChildStdError_Wr);
  }

  SAFE_DELETE_ARRAY(paramsAlloc);

  if(!retValue)
  {
    if(!internal)
      RDCWARN("Process %s could not be loaded (error %d).", app.c_str(), err);

    // diagnostic: log CreateProcessW failure details
    {
      char diagBuf[512];
      wsprintfA(diagBuf,
                "[SQC-DIAG] RunProcess FAILED: tick=%u app='%s' workdir='%s' err=%u "
                "(0x%08X)\r\n",
                GetTickCount(), app.c_str(), workingDir.c_str(), err, err);
      SqcDiagLog(diagBuf);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    RDCEraseEl(pi);
  }

  return pi;
}

static bool SqcLaunchEnvSets(const rdcarray<EnvironmentModification> &env, const rdcstr &name,
                             const rdcstr &value)
{
  const rdcstr lowerName = strlower(name);
  for(const EnvironmentModification &e : env)
  {
    if(strlower(e.name) == lowerName && e.mod == EnvMod::Set && e.value == value)
      return true;
  }

  return false;
}

static bool SqcLaunchEnvEnabled(const rdcarray<EnvironmentModification> &env, const rdcstr &name)
{
  return Process::GetEnvVariable(name) == "1" || SqcLaunchEnvSets(env, name, "1");
}

static void AddEnvMod(rdcarray<EnvironmentModification> &env, const rdcstr &name,
                      const rdcstr &value);
static void AddYuanShenDirectEnv(rdcarray<EnvironmentModification> &env);

static void SqcDiagLogEnvState(const char *label, const rdcarray<EnvironmentModification> &env)
{
  SqcDiagLog(StringFormat::Fmt(
                 "[SQC-DIAG] EnvState %s direct=%u d3d11DxgiOnly=%u inlineHooks=%u proxy=%u swapWrap=%u targetControlOnly=%u rawD3D11=%u disableBootstrap=%u disableMinimal=%u\r\n",
                 label, SqcLaunchEnvEnabled(env, "SQC_YUANSHEN_DIRECT_SYSTEM_LOAD") ? 1 : 0,
                 SqcLaunchEnvEnabled(env, "SQC_D3D11_LIGHT_HOOKS") ? 1 : 0,
                 SqcLaunchEnvEnabled(env, "SQC_YUANSHEN_INLINE_HOOKS") ? 1 : 0,
                 SqcLaunchEnvEnabled(env, "SQC_D3D11_PROXY") ? 1 : 0,
                 SqcLaunchEnvEnabled(env, "SQC_YUANSHEN_SWAPCHAIN_WRAP") ? 1 : 0,
                 SqcLaunchEnvEnabled(env, "SQC_TARGET_CONTROL_ONLY") ? 1 : 0,
                 SqcLaunchEnvEnabled(env, "SQC_D3D11_RAW_PASSTHROUGH") ? 1 : 0,
                 SqcLaunchEnvEnabled(env, "SQC_DISABLE_YUANSHEN_BOOTSTRAP_ONLY") ? 1 : 0,
                 SqcLaunchEnvEnabled(env, "SQC_DISABLE_YUANSHEN_MINIMAL_LOAD") ? 1 : 0)
                 .c_str());
}

rdcpair<RDResult, uint32_t> Process::InjectIntoProcess(uint32_t pid,
                                                       const rdcarray<EnvironmentModification> &env,
                                                       const rdcstr &capturefile,
                                                       const CaptureOptions &opts, bool waitForExit)
{
  if(Process::IsInjectionBlockedProcess(pid))
  {
    RDResult result;
    SET_ERROR_RESULT(result, ResultCode::InjectionFailed,
                     "Process %u matches the SanQi Capture injection blocklist.", pid);
    return {result, 0};
  }

  rdcwstr wcapturefile = StringFormat::UTF82Wide(capturefile);
  rdcarray<EnvironmentModification> injectEnv = env;

  HANDLE hProcess =
      OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                      PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE,
                  FALSE, pid);

  if(hProcess == NULL)
  {
    DWORD err = GetLastError();
    SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] InjectIntoProcess OpenProcess failed pid=%u err=%u\r\n",
                                 pid, err)
                   .c_str());

    RDResult result;
    SET_ERROR_RESULT(result, ResultCode::InjectionFailed,
                     "Failed to open process %u for injection (err %u).", pid, err);
    return {result, 0};
  }

  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] InjectIntoProcess OpenProcess OK pid=%u\r\n", pid)
                 .c_str());

  if(opts.delayForDebugger > 0)
  {
    RDCDEBUG("Waiting for debugger attach to %lu", pid);
    uint32_t timeout = 0;

    BOOL debuggerAttached = FALSE;

    while(!debuggerAttached)
    {
      CheckRemoteDebuggerPresent(hProcess, &debuggerAttached);

      Sleep(10);
      timeout += 10;

      if(timeout > opts.delayForDebugger * 1000)
        break;
    }

    if(debuggerAttached)
      RDCDEBUG("Debugger attach detected after %.2f s", float(timeout) / 1000.0f);
    else
      RDCDEBUG("Timed out waiting for debugger, gave up after %u s", opts.delayForDebugger);
  }

  RDCLOG("Injecting sqcap library into process %lu", pid);

  wchar_t renderdocPath[MAX_PATH] = {0};
  HMODULE selfModule = GetModuleHandleA(STRINGIZE(RDOC_BASE_NAME) ".dll");
  if(selfModule == NULL)
    selfModule = GetCachedSelfModuleHandle();
  GetModuleFileNameW(selfModule, &renderdocPath[0], MAX_PATH - 1);

  bool yuanShenBootstrapDeferred = false;
  wchar_t originalRenderdocPath[MAX_PATH] = {};
  rdcstr yuanShenBootstrapIdentFile;
  wcscpy_s(originalRenderdocPath, renderdocPath);
  const bool yuanShenTarget = IsYuanShenProcess(hProcess);
  if(yuanShenTarget)
  {
    if(!SqcLaunchEnvEnabled(injectEnv, "SQC_YUANSHEN_DIRECT_SYSTEM_LOAD") &&
       !SqcLaunchEnvEnabled(injectEnv, "SQC_D3D11_PROXY"))
    {
      AddYuanShenDirectEnv(injectEnv);
      SqcDiagLog("[SQC-DIAG] YuanShen direct system_load inject env forced because D3D11 proxy is off\r\n");
    }
    yuanShenBootstrapDeferred =
        !SqcLaunchEnvEnabled(injectEnv, "SQC_YUANSHEN_DIRECT_SYSTEM_LOAD") &&
        !SqcLaunchEnvEnabled(injectEnv, "SQC_DISABLE_YUANSHEN_BOOTSTRAP_ONLY");
  }

  SqcDiagLog(StringFormat::Fmt(
                 "[SQC-DIAG] YuanShen inject decision target=%u direct=%u proxy=%u bootstrapDeferred=%u\r\n",
                 yuanShenTarget ? 1 : 0,
                 SqcLaunchEnvEnabled(injectEnv, "SQC_YUANSHEN_DIRECT_SYSTEM_LOAD") ? 1 : 0,
                 SqcLaunchEnvEnabled(injectEnv, "SQC_D3D11_PROXY") ? 1 : 0,
                 yuanShenBootstrapDeferred ? 1 : 0)
                 .c_str());
  SqcDiagLogEnvState("inject", injectEnv);

  if(yuanShenBootstrapDeferred)
  {
    wchar_t *slash = wcsrchr(renderdocPath, L'\\');
    if(slash)
    {
      slash[1] = 0;
      wcscat_s(renderdocPath, L"d3d11_proxy.dll");

      wchar_t identPath[MAX_PATH] = {};
      GetTempPathW(MAX_PATH, identPath);
      wcscat_s(identPath, L"sqc_proxy_bootstrap_ident_");
      wchar_t pidText[32] = {};
      swprintf_s(pidText, L"%u.txt", pid);
      wcscat_s(identPath, pidText);

      SetEnvironmentVariableA("SQC_PROXY_IDENT_FILE",
                              StringFormat::Wide2UTF8(identPath).c_str());

      yuanShenBootstrapIdentFile = StringFormat::Wide2UTF8(identPath);
      rdcstr sidecarPath = StringFormat::Wide2UTF8(renderdocPath) + ".sqcproxy";
      rdcstr sidecarContents = StringFormat::Fmt("%s\n%s\n%s\n%s\n%s\ndefer_capture\n",
                                                 StringFormat::Wide2UTF8(originalRenderdocPath).c_str(),
                                                 capturefile.c_str(), opts.EncodeAsString().c_str(),
                                                 RDCGETLOGFILE(),
                                                 StringFormat::Wide2UTF8(identPath).c_str());
      FileIO::WriteAll(sidecarPath, sidecarContents);
      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] YuanShen bootstrap-deferred payload='%s' systemLoad='%s' identFile='%s' sidecar='%s'\r\n",
                     StringFormat::Wide2UTF8(renderdocPath).c_str(),
                     StringFormat::Wide2UTF8(originalRenderdocPath).c_str(),
                     StringFormat::Wide2UTF8(identPath).c_str(), sidecarPath.c_str())
                     .c_str());
    }
  }

  // Diagnose injector path resolution
  {
    char diagBuf[512];
    wsprintfA(diagBuf, "[SQC-DIAG] InjectIntoProcess: tick=%u sqcapPath='%ls' err=%u\r\n",
              GetTickCount(), renderdocPath, GetLastError());
    SqcDiagLog(diagBuf);
  }

  wchar_t renderdocPathLower[MAX_PATH] = {0};
  memcpy(renderdocPathLower, renderdocPath, MAX_PATH * sizeof(wchar_t));
  for(size_t i = 0; i < MAX_PATH && renderdocPathLower[i]; i++)
  {
    // lowercase
    if(renderdocPathLower[i] >= 'A' && renderdocPathLower[i] <= 'Z')
      renderdocPathLower[i] = 'a' + char(renderdocPathLower[i] - 'A');

    // normalise paths
    if(renderdocPathLower[i] == '/')
      renderdocPathLower[i] = '\\';
  }

  BOOL isWow64 = FALSE;
  BOOL success = IsWow64Process(hProcess, &isWow64);

  if(!success)
  {
    DWORD err = GetLastError();
    RDResult result;
    SET_ERROR_RESULT(result, ResultCode::IncompatibleProcess,
                     "Couldn't determine bitness of process, err: %08x", err);
    CloseHandle(hProcess);
    return {result, 0};
  }

  bool capalt = false;

#if DISABLED(RDOC_X64)
  BOOL selfWow64 = FALSE;

  HANDLE hSelfProcess = GetCurrentProcess();

  // check to see if we're a WoW64 process
  success = IsWow64Process(hSelfProcess, &selfWow64);

  CloseHandle(hSelfProcess);

  if(!success)
  {
    DWORD err = GetLastError();
    RDResult result;
    SET_ERROR_RESULT(result, ResultCode::IncompatibleProcess,
                     "Couldn't determine bitness of self, err: %08x", err);
    CloseHandle(hProcess);
    return {result, 0};
  }

  // we know we're 32-bit, so if the target process is not wow64
  // and we are, it's 64-bit. If we're both not wow64 then we're
  // running on 32-bit windows, and if we're both wow64 then we're
  // both 32-bit on 64-bit windows.
  //
  // We don't support capturing 64-bit programs from a 32-bit install
  // because it's pointless - a 64-bit install will work for all in
  // that case. But we do want to handle the case of:
  // 64-bit renderdoc -> 32-bit program (via 32-bit sanqicapture)
  //    -> 64-bit program (going back to 64-bit sanqicapture).
  // so we try to see if we're an x86 invoked sanqicapture in an
  // otherwise 64-bit install, and 'promote' back to 64-bit.
  if(selfWow64 && !isWow64)
  {
    wchar_t *slash = wcsrchr(renderdocPath, L'\\');

    if(slash && slash > renderdocPath + 4)
    {
      slash -= 4;

      if(slash && !wcsncmp(slash, L"\\x86", 4))
      {
        RDCDEBUG("Promoting back to 64-bit");
        capalt = true;
      }
    }

    // if it looks like we're in the development environment, look for the alternate bitness in the
    // corresponding folder
    if(!capalt)
    {
      const wchar_t *devLocation = wcsstr(renderdocPathLower, L"\\win32\\development\\");
      if(!devLocation)
        devLocation = wcsstr(renderdocPathLower, L"\\win32\\release\\");

      if(devLocation)
      {
        RDCDEBUG("Promoting back to 64-bit");
        capalt = true;
      }
    }

    // if we couldn't promote, then bail out.
    if(!capalt)
    {
      RDCDEBUG("Running from %ls", renderdocPathLower);

      CloseHandle(hProcess);
      RDResult result;
      SET_ERROR_RESULT(result, ResultCode::IncompatibleProcess,
                       "Can't capture 64-bit program with 32-bit build of SanQi Capture. Please run a "
                       "64-bit build of SanQi Capture");
      return {result, 0};
    }
  }
#else
  // farm off to alternate bitness sanqicapture.exe

  // if the target process is 'wow64' that means it's 32-bit.
  capalt = (isWow64 == TRUE);
#endif

  if(capalt)
  {
#if ENABLED(RDOC_X64)
    // if it looks like we're in the development environment, look for the alternate bitness in the
    // corresponding folder
    const wchar_t *devLocation = wcsstr(renderdocPathLower, L"\\x64\\development\\");
    if(devLocation)
    {
      size_t idx = devLocation - renderdocPathLower;

      renderdocPath[idx] = 0;

      wcscat_s(renderdocPath, L"\\Win32\\Development\\sanqicapture.exe");
    }

    if(!devLocation)
    {
      devLocation = wcsstr(renderdocPathLower, L"\\x64\\release\\");

      if(devLocation)
      {
        size_t idx = devLocation - renderdocPathLower;

        renderdocPath[idx] = 0;

        wcscat_s(renderdocPath, L"\\Win32\\Release\\sanqicapture.exe");
      }
    }

    if(!devLocation)
    {
      // look in a subfolder for x86.

      // remove the filename from the path
      wchar_t *slash = wcsrchr(renderdocPath, L'\\');

      if(slash)
        *slash = 0;

      // append path
      wcscat_s(renderdocPath, L"\\x86\\sanqicapture.exe");
    }
#else
    // if it looks like we're in the development environment, look for the alternate bitness in the
    // corresponding folder
    const wchar_t *devLocation = wcsstr(renderdocPathLower, L"\\win32\\development\\");
    if(devLocation)
    {
      size_t idx = devLocation - renderdocPathLower;

      renderdocPath[idx] = 0;

      wcscat_s(renderdocPath, L"\\x64\\Development\\sanqicapture.exe");
    }

    if(!devLocation)
    {
      devLocation = wcsstr(renderdocPathLower, L"\\win32\\release\\");

      if(devLocation)
      {
        size_t idx = devLocation - renderdocPathLower;

        renderdocPath[idx] = 0;

        wcscat_s(renderdocPath, L"\\x64\\Release\\sanqicapture.exe");
      }
    }

    if(!devLocation)
    {
      // look upwards on 32-bit to find the parent sanqicapture.
      wchar_t *slash = wcsrchr(renderdocPath, L'\\');

      // remove the filename
      if(slash)
        *slash = 0;

      // remove the \\x86
      slash = wcsrchr(renderdocPath, L'\\');

      if(slash)
        *slash = 0;

      // append path
      wcscat_s(renderdocPath, L"\\sanqicapture.exe");
    }
#endif

    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    SECURITY_ATTRIBUTES pSec;
    SECURITY_ATTRIBUTES tSec;

    RDCEraseEl(pi);
    RDCEraseEl(si);
    RDCEraseEl(pSec);
    RDCEraseEl(tSec);

    // hide the console window
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    pSec.nLength = sizeof(pSec);
    tSec.nLength = sizeof(tSec);

    // serialise to string with two chars per byte
    rdcstr optstr = opts.EncodeAsString();

    wchar_t *paramsAlloc = new wchar_t[2048];

    rdcstr debugLogfile = RDCGETLOGFILE();
    rdcwstr wdebugLogfile = StringFormat::UTF82Wide(debugLogfile);

    _snwprintf_s(
        paramsAlloc, 2047, 2047,
        L"\"%ls\" capaltbit --pid=%u --capfile=\"%ls\" --debuglog=\"%ls\" --capopts=\"%hs\"",
        renderdocPath, pid, wcapturefile.c_str(), wdebugLogfile.c_str(), optstr.c_str());

    RDCDEBUG("params %ls", paramsAlloc);

    paramsAlloc[2047] = 0;

    wchar_t *commandLine = paramsAlloc;

    std::wstring cmdWithEnv;

    if(!injectEnv.empty())
    {
      cmdWithEnv = paramsAlloc;

      for(const EnvironmentModification &e : injectEnv)
      {
        rdcstr name = e.name.trimmed();
        rdcstr value = e.value;

        if(name == "")
          break;

        cmdWithEnv += L" +env-";
        switch(e.mod)
        {
          case EnvMod::Set: cmdWithEnv += L"replace"; break;
          case EnvMod::Append: cmdWithEnv += L"append"; break;
          case EnvMod::Prepend: cmdWithEnv += L"prepend"; break;
        }

        if(e.mod != EnvMod::Set)
        {
          switch(e.sep)
          {
            case EnvSep::Platform: cmdWithEnv += L"-platform"; break;
            case EnvSep::SemiColon: cmdWithEnv += L"-semicolon"; break;
            case EnvSep::Colon: cmdWithEnv += L"-colon"; break;
            case EnvSep::NoSep: break;
          }
        }

        cmdWithEnv += L" ";

        // escape the parameters
        for(size_t it = 0; it < name.size(); it++)
        {
          if(name[it] == '"')
          {
            name.insert(it, '\\');
            it++;
          }
        }

        for(size_t it = 0; it < value.size(); it++)
        {
          if(value[it] == '"')
          {
            value.insert(it, '\\');
            it++;
          }
        }

        if(name.back() == '\\')
          name += "\\";

        if(value.back() == '\\')
          value += "\\";

        cmdWithEnv += L"\"" + std::wstring(StringFormat::UTF82Wide(name).c_str()) + L"\" ";
        cmdWithEnv += L"\"" + std::wstring(StringFormat::UTF82Wide(value).c_str()) + L"\" ";
      }

      commandLine = (wchar_t *)cmdWithEnv.c_str();
    }

    BOOL retValue = CreateProcessW(NULL, commandLine, &pSec, &tSec, false,
                                   CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    SAFE_DELETE_ARRAY(paramsAlloc);

    if(!retValue)
    {
      RDResult result;
#if RENDERDOC_OFFICIAL_BUILD
      SET_ERROR_RESULT(result, ResultCode::InternalError,
                       "Can't run 32-bit sanqicapture to capture 32-bit program.");
#else
      SET_ERROR_RESULT(
          result, ResultCode::InternalError,
          "Can't run 32-bit sanqicapture to capture 32-bit program."
          "If this is a locally built SanQi Capture you must build both 32-bit and 64-bit versions.");
#endif
      CloseHandle(hProcess);
      return {result, 0};
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hThread, INFINITE);
    CloseHandle(pi.hThread);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);

    if(waitForExit)
      WaitForSingleObject(hProcess, INFINITE);

    CloseHandle(hProcess);

    if(exitCode == 0)
    {
      RDResult result;
      SET_ERROR_RESULT(result, ResultCode::UnknownError,
                       "Encountered error while launching target 32-bit program.");
      return {result, 0};
    }

    if(exitCode < RenderDoc_FirstTargetControlPort)
    {
      ResultCode code = (ResultCode)exitCode;

      RDResult result;
      SET_ERROR_RESULT(result, code, "32-bit sanqicapture returned '%s'", ToStr(code).c_str());
      return {code, 0};
    }

    return {ResultCode::Succeeded, (uint32_t)exitCode};
  }

  const char *rdoc_dll = STRINGIZE(RDOC_BASE_NAME);

  rdcpair<RDResult, uint32_t> result = {ResultCode::Succeeded, 0};

  const bool directSystemLoad =
      yuanShenTarget && SqcLaunchEnvEnabled(injectEnv, "SQC_YUANSHEN_DIRECT_SYSTEM_LOAD");
  HANDLE directInjectionCompleteEvent = NULL;
  HANDLE directHooksReadyEvent = NULL;
  HANDLE directHooksFailedEvent = NULL;
  if(directSystemLoad)
  {
    wchar_t eventName[64] = {};
    swprintf_s(eventName, L"Local\\SQC_InjectComplete_%u", pid);
    directInjectionCompleteEvent = CreateEventW(NULL, TRUE, FALSE, eventName);
    swprintf_s(eventName, L"Local\\SQC_HooksReady_%u", pid);
    directHooksReadyEvent = CreateEventW(NULL, TRUE, FALSE, eventName);
    swprintf_s(eventName, L"Local\\SQC_HooksFailed_%u", pid);
    directHooksFailedEvent = CreateEventW(NULL, TRUE, FALSE, eventName);

    if(directInjectionCompleteEvent == NULL || directHooksReadyEvent == NULL ||
       directHooksFailedEvent == NULL)
    {
      SET_ERROR_RESULT(result.first, ResultCode::InjectionFailed,
                       "Failed to create capture hook status events for process %u.", pid);
      if(directHooksFailedEvent != NULL)
        CloseHandle(directHooksFailedEvent);
      if(directHooksReadyEvent != NULL)
        CloseHandle(directHooksReadyEvent);
      if(directInjectionCompleteEvent != NULL)
        CloseHandle(directInjectionCompleteEvent);
      CloseHandle(hProcess);
      return result;
    }
  }

  if(!InjectDLL(hProcess, renderdocPath))
  {
    rdcstr failure = InjectDLLFailure.empty() ? "no detailed failure was recorded" : InjectDLLFailure;
    SET_ERROR_RESULT(result.first, ResultCode::InjectionFailed,
                      "Timed out or failed loading %s.dll into process: %s.", rdoc_dll,
                      failure.c_str());
    if(directHooksFailedEvent != NULL)
      CloseHandle(directHooksFailedEvent);
    if(directHooksReadyEvent != NULL)
      CloseHandle(directHooksReadyEvent);
    if(directInjectionCompleteEvent != NULL)
      CloseHandle(directInjectionCompleteEvent);
    CloseHandle(hProcess);
    return result;
  }

  if(directSystemLoad)
  {
    uintptr_t remoteModule = FindRemoteDLL(pid, STRINGIZE(RDOC_BASE_NAME) ".dll");
    const rdcstr encodedOptions = opts.EncodeAsString();
    bool directConfigOK = remoteModule != 0;

    if(directConfigOK)
    {
      directConfigOK = InjectFunctionCall(hProcess, remoteModule, "INTERNAL_SetCaptureFile",
                                          (void *)capturefile.c_str(), capturefile.size() + 1);
    }

    if(directConfigOK)
    {
      directConfigOK = InjectFunctionCall(
          hProcess, remoteModule, "INTERNAL_StartYuanShenDirectHooks",
          (void *)encodedOptions.c_str(), encodedOptions.size() + 1);
    }

    if(!directConfigOK)
    {
      SET_ERROR_RESULT(result.first, ResultCode::InjectionFailed,
                       "Failed to configure and start direct capture hooks in process %u.", pid);
      SignalInjectionComplete(pid);
      if(directHooksFailedEvent != NULL)
        CloseHandle(directHooksFailedEvent);
      if(directHooksReadyEvent != NULL)
        CloseHandle(directHooksReadyEvent);
      if(directInjectionCompleteEvent != NULL)
        CloseHandle(directInjectionCompleteEvent);
      CloseHandle(hProcess);
      return result;
    }
  }

  SignalInjectionComplete(pid);

  if(yuanShenBootstrapDeferred)
  {
    result.second = WaitForProxyIdentFile(yuanShenBootstrapIdentFile, hProcess, 20000);
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] YuanShen bootstrap-deferred injected pid=%u ident=%u\r\n", pid,
                   result.second)
                   .c_str());

    if(result.second == 0)
    {
      SET_ERROR_RESULT(result.first, ResultCode::InjectionFailed,
                       "Timed out waiting for deferred capture bootstrap target control.");
    }

    CloseHandle(hProcess);
    return result;
  }

  const bool targetControlOnly = SqcLaunchEnvEnabled(injectEnv, "SQC_TARGET_CONTROL_ONLY") &&
                                 !SqcLaunchEnvEnabled(
                                     injectEnv, "SQC_DISABLE_YUANSHEN_TARGET_CONTROL_ONLY");
  const bool minimalYuanshenLoad =
      IsYuanShenProcess(hProcess) && (directSystemLoad || targetControlOnly);

  if(minimalYuanshenLoad)
  {
    result.second = WaitForTargetIdentFile(pid, hProcess, 10000);
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] MinimalLoad skip remote lookup/config pid=%u identFile=%u\r\n", pid,
                   result.second)
                   .c_str());

    if(result.second == 0)
    {
      SET_ERROR_RESULT(result.first, ResultCode::InjectionFailed,
                       "Injected %s.dll did not report a target control connection.", rdoc_dll);
    }

    if(directSystemLoad && result.second != 0)
    {
      HANDLE hookStatusEvents[] = {directHooksReadyEvent, directHooksFailedEvent};
      DWORD hookStatus =
          WaitForMultipleObjects(ARRAY_COUNT(hookStatusEvents), hookStatusEvents, FALSE, 15000);
      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] DirectInject HookStatus wait pid=%u result=%u err=%u\r\n", pid,
                     hookStatus, hookStatus == WAIT_FAILED ? GetLastError() : 0)
                     .c_str());

      if(hookStatus == WAIT_OBJECT_0 + 1)
      {
        SET_ERROR_RESULT(result.first, ResultCode::InjectionFailed,
                         "Target process %u failed to register capture hooks.", pid);
      }
      else if(hookStatus != WAIT_OBJECT_0)
      {
        SET_ERROR_RESULT(result.first, ResultCode::InjectionFailed,
                         "Timed out waiting for target process %u capture hooks.", pid);
      }
    }

    if(directHooksFailedEvent != NULL)
      CloseHandle(directHooksFailedEvent);
    if(directHooksReadyEvent != NULL)
      CloseHandle(directHooksReadyEvent);
    if(directInjectionCompleteEvent != NULL)
      CloseHandle(directInjectionCompleteEvent);

    if(waitForExit)
      WaitForSingleObject(hProcess, INFINITE);
    CloseHandle(hProcess);
    return result;
  }

  uintptr_t loc = FindRemoteDLL(pid, STRINGIZE(RDOC_BASE_NAME) ".dll");

  if(loc == 0)
  {
    SET_ERROR_RESULT(
        result.first, ResultCode::InjectionFailed,
        "Failed to inject %s.dll into process. Check that the process did not crash or exit "
        "early in initialisation, e.g. if the working directory is incorrectly set.",
        rdoc_dll);
  }
  else
  {
    // safe to cast away the const as we know these functions don't modify the parameters
    bool setupOK = true;
    bool captureTemplateConfigured = capturefile.empty();
    const char *failedFunc = NULL;
    if(!capturefile.empty())
    {
      setupOK = InjectFunctionCall(hProcess, loc, "INTERNAL_SetCaptureFile",
                                   (void *)capturefile.c_str(), capturefile.size() + 1);
      if(setupOK)
        captureTemplateConfigured = true;
      else
        failedFunc = "INTERNAL_SetCaptureFile";
    }

    if(setupOK && Process::GetEnvVariable("SQC_REMOTE_DEBUG_LOG") == "1")
    {
      rdcstr debugLogfile = RDCGETLOGFILE();
      setupOK = InjectFunctionCall(hProcess, loc, "INTERNAL_SetDebugLogFile",
                                   (void *)debugLogfile.c_str(), debugLogfile.size() + 1);
      if(!setupOK)
        failedFunc = "INTERNAL_SetDebugLogFile";
    }

    if(setupOK)
    {
      setupOK = InjectFunctionCall(hProcess, loc, "INTERNAL_SetCaptureOptions",
                                   (CaptureOptions *)&opts, sizeof(CaptureOptions));
      if(!setupOK)
        failedFunc = "INTERNAL_SetCaptureOptions";
    }

    if(setupOK)
    {
      result.second = ReadTargetIdentFile(pid);
      if(result.second == 0)
      {
        setupOK = InjectFunctionCall(hProcess, loc, "INTERNAL_GetTargetControlIdent",
                                     &result.second, sizeof(result.second));
        if(!setupOK)
          failedFunc = "INTERNAL_GetTargetControlIdent";
      }
    }

    if(setupOK && !injectEnv.empty())
    {
      for(const EnvironmentModification &e : injectEnv)
      {
        rdcstr name = e.name.trimmed();
        rdcstr value = e.value;
        EnvMod mod = e.mod;
        EnvSep sep = e.sep;

        if(name == "")
          break;

        setupOK = InjectFunctionCall(hProcess, loc, "INTERNAL_EnvModName", (void *)name.c_str(),
                                     name.size() + 1);
        if(setupOK)
          setupOK = InjectFunctionCall(hProcess, loc, "INTERNAL_EnvModValue",
                                       (void *)value.c_str(), value.size() + 1);
        if(setupOK)
          setupOK = InjectFunctionCall(hProcess, loc, "INTERNAL_EnvSep", &sep, sizeof(sep));
        if(setupOK)
          setupOK = InjectFunctionCall(hProcess, loc, "INTERNAL_EnvMod", &mod, sizeof(mod));
        if(!setupOK)
        {
          failedFunc = "INTERNAL_EnvMod*";
          break;
        }
      }

      // parameter is unused
      void *dummy = NULL;
      if(setupOK)
      {
        setupOK = InjectFunctionCall(hProcess, loc, "INTERNAL_ApplyEnvMods", &dummy,
                                     sizeof(dummy));
        if(!setupOK)
          failedFunc = "INTERNAL_ApplyEnvMods";
      }
    }

    if(!setupOK)
    {
      uint32_t ident = ReadTargetIdentFile(pid);
      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] Inject config failed func=%s captureTemplate=%u identFile=%u\r\n",
                     failedFunc ? failedFunc : "<unknown>", captureTemplateConfigured ? 1 : 0,
                     ident)
                     .c_str());

      if(captureTemplateConfigured && ident != 0)
      {
        result.first = ResultCode::Succeeded;
        result.second = ident;
        SqcDiagLog(StringFormat::Fmt(
                       "[SQC-DIAG] Inject config fallback success pid=%u ident=%u\r\n", pid,
                       ident)
                       .c_str());
      }
      else
      {
        SET_ERROR_RESULT(result.first, ResultCode::InjectionFailed,
                         "Timed out or failed configuring injected %s.dll at %s.", rdoc_dll,
                         failedFunc ? failedFunc : "unknown step");
        result.second = 0;
      }
    }
    else if(result.second == 0)
    {
      result.second = ReadTargetIdentFile(pid);
    }

    if(setupOK && result.second == 0)
    {
      SET_ERROR_RESULT(result.first, ResultCode::InjectionFailed,
                       "Injected %s.dll did not report a target control connection.", rdoc_dll);
    }
  }

  if(waitForExit)
    WaitForSingleObject(hProcess, INFINITE);

  CloseHandle(hProcess);

  return result;
}

uint32_t Process::LaunchProcess(const rdcstr &app, const rdcstr &workingDir, const rdcstr &cmdLine,
                                bool internal, ProcessResult *result)
{
  HANDLE hChildStdOutput_Rd = NULL, hChildStdError_Rd = NULL;

  rdcstr appPath = app;
  size_t len = appPath.length();
  rdcstr ext;
  if(len > 4)
    ext = strlower(appPath.substr(len - 4));
  if(ext != ".exe")
    appPath += ".exe";

  PROCESS_INFORMATION pi =
      RunProcess(appPath, workingDir, cmdLine, {}, internal, result ? &hChildStdOutput_Rd : NULL,
                 result ? &hChildStdError_Rd : NULL);

  if(pi.dwProcessId == 0)
  {
    if(!internal)
      RDCWARN("Couldn't launch process '%s'", appPath.c_str());

    if(hChildStdError_Rd != NULL)
      CloseHandle(hChildStdError_Rd);
    if(hChildStdOutput_Rd != NULL)
      CloseHandle(hChildStdOutput_Rd);

    return 0;
  }

  if(!internal)
    RDCLOG("Launched process '%s' with '%s'", appPath.c_str(), cmdLine.c_str());

  ResumeThread(pi.hThread);

  if(result)
  {
    result->strStdout = "";
    result->strStderror = "";

    char chBuf[4096];
    DWORD dwOutputRead, dwErrorRead;
    BOOL success = FALSE;
    rdcstr s;
    for(;;)
    {
      success = ReadFile(hChildStdOutput_Rd, chBuf, sizeof(chBuf), &dwOutputRead, NULL);
      s = rdcstr(chBuf, dwOutputRead);
      result->strStdout += s;

      if(!success && !dwOutputRead)
        break;
    }

    for(;;)
    {
      success = ReadFile(hChildStdError_Rd, chBuf, sizeof(chBuf), &dwErrorRead, NULL);
      s = rdcstr(chBuf, dwErrorRead);
      result->strStderror += s;

      if(!success && !dwErrorRead)
        break;
    }

    CloseHandle(hChildStdOutput_Rd);
    CloseHandle(hChildStdError_Rd);

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, (LPDWORD)&result->retCode);
  }

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  return pi.dwProcessId;
}

uint32_t Process::LaunchScript(const rdcstr &script, const rdcstr &workingDir,
                               const rdcstr &argList, bool internal, ProcessResult *result)
{
  // Change parameters to invoke command interpreter
  rdcstr args = "/C " + script + " " + argList;

  return LaunchProcess("cmd.exe", workingDir, args, internal, result);
}

static void AddEnvMod(rdcarray<EnvironmentModification> &env, const rdcstr &name,
                      const rdcstr &value)
{
  EnvironmentModification mod;
  mod.name = name;
  mod.value = value;
  mod.mod = EnvMod::Set;
  mod.sep = EnvSep::NoSep;
  env.push_back(mod);
}

static void AddYuanShenDirectEnv(rdcarray<EnvironmentModification> &env)
{
  AddEnvMod(env, "SQC_YUANSHEN_DIRECT_SYSTEM_LOAD", "1");
  AddEnvMod(env, "SQC_D3D11_LIGHT_HOOKS", "1");
  AddEnvMod(env, "SQC_YUANSHEN_INLINE_HOOKS", "1");
}

static bool IsYuanShenLaunchTarget(const rdcstr &app)
{
  return strlower(get_basename(app)) == "yuanshen.exe";
}

static bool WantsD3D11Proxy(const rdcarray<EnvironmentModification> &env)
{
  for(const EnvironmentModification &e : env)
  {
    if(strlower(e.name) == "sqc_d3d11_proxy" && e.mod == EnvMod::Set && e.value == "1")
      return true;
  }

  return false;
}

static rdcstr SiblingPath(const rdcstr &path, const rdcstr &filename)
{
  return get_dirname(path) + "/" + filename;
}

static uint32_t ReadProxyIdent(const rdcstr &identFile)
{
  FILE *f = FileIO::fopen(identFile, FileIO::ReadText);
  if(f == NULL)
    return 0;

  char buf[64] = {};
  size_t read = fread(buf, 1, sizeof(buf) - 1, f);
  FileIO::fclose(f);

  if(read == 0)
    return 0;

  return (uint32_t)strtoul(buf, NULL, 10);
}

static uint32_t WaitForProxyIdentFile(const rdcstr &identFile, HANDLE process, DWORD timeoutMS)
{
  DWORD start = GetTickCount();
  DWORD exitCode = STILL_ACTIVE;

  for(;;)
  {
    uint32_t ident = ReadProxyIdent(identFile);
    if(ident != 0)
      return ident;

    if(process != NULL && GetExitCodeProcess(process, &exitCode) && exitCode != STILL_ACTIVE)
      return 0;

    if(GetTickCount() - start >= timeoutMS)
      return 0;

    Sleep(100);
  }
}

static bool IsSanQiD3D11ProxyPayload(const rdcstr &path)
{
  rdcstr contents;
  if(!FileIO::ReadAll(path, contents))
    return false;

  return contents.contains("SQC_D3D11_PROXY_PAYLOAD_V1") ||
         contents.contains("sqc_d3d11_proxy.txt");
}

static bool ContainsPID(const rdcarray<DWORD> &pids, DWORD pid)
{
  for(DWORD existing : pids)
  {
    if(existing == pid)
      return true;
  }

  return false;
}

static void CaptureExistingProcessPIDs(rdcarray<DWORD> &pids)
{
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(snapshot == INVALID_HANDLE_VALUE)
    return;

  PROCESSENTRY32 pe32 = {};
  pe32.dwSize = sizeof(PROCESSENTRY32);

  if(Process32First(snapshot, &pe32))
  {
    do
    {
      if(!ContainsPID(pids, pe32.th32ProcessID))
        pids.push_back(pe32.th32ProcessID);
    } while(Process32Next(snapshot, &pe32));
  }

  CloseHandle(snapshot);
}

static rdcstr NormaliseWinProcessPath(const rdcstr &path)
{
  char fullPath[32768] = {};
  DWORD len = GetFullPathNameA(path.c_str(), (DWORD)sizeof(fullPath), fullPath, NULL);
  rdcstr ret = (len > 0 && len < sizeof(fullPath)) ? rdcstr(fullPath) : path;
  return strlower(standardise_directory_separator(ret));
}

static bool GetProcessImagePath(DWORD pid, rdcstr &path)
{
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if(hProcess == NULL)
    return false;

  char processName[32768] = {};
  DWORD size = sizeof(processName);
  bool ret = QueryFullProcessImageNameA(hProcess, 0, processName, &size) != FALSE;
  CloseHandle(hProcess);

  if(ret)
    path = processName;

  return ret;
}

static DWORD FindMatchingProcessByPath(const rdcstr &targetPath, DWORD launchedPid,
                                       const rdcarray<DWORD> &attemptedPids,
                                       rdcarray<DWORD> &seenPids)
{
  const rdcstr target = NormaliseWinProcessPath(targetPath);
  const rdcstr targetBase = strlower(get_basename(targetPath));

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(snapshot == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32 pe32 = {};
  pe32.dwSize = sizeof(PROCESSENTRY32);

  DWORD matchedPid = 0;
  if(Process32First(snapshot, &pe32))
  {
    do
    {
      DWORD pid = pe32.th32ProcessID;
      bool newlySeen = !ContainsPID(seenPids, pid);
      if(newlySeen)
        seenPids.push_back(pid);

      if(pid == 0 || pid == 4 || pid == GetCurrentProcessId() || pid == launchedPid ||
         ContainsPID(attemptedPids, pid))
      {
        continue;
      }

      rdcstr processPath;
      bool havePath = GetProcessImagePath(pid, processPath);
      rdcstr displayPath = havePath ? processPath : StringFormat::Wide2UTF8(pe32.szExeFile);
      bool blocked = Process::IsInjectionBlockedProcess(pid);
      bool basenameMatch = strlower(get_basename(displayPath)) == targetBase;
      bool pathMatch = havePath && NormaliseWinProcessPath(processPath) == target;

      if(newlySeen)
      {
        rdcstr parentPath;
        GetProcessImagePath(pe32.th32ParentProcessID, parentPath);
        SqcDiagLog(StringFormat::Fmt(
                       "[SQC-DIAG] RelaunchWait candidate pid=%u parent=%u exe='%s' path='%s' parentPath='%s' blocked=%u basenameMatch=%u pathMatch=%u\r\n",
                       pid, pe32.th32ParentProcessID,
                       StringFormat::Wide2UTF8(pe32.szExeFile).c_str(), displayPath.c_str(),
                       parentPath.c_str(), blocked ? 1 : 0, basenameMatch ? 1 : 0,
                       pathMatch ? 1 : 0)
                       .c_str());
      }

      if(!havePath || blocked)
        continue;

      rdcstr normalisedPath = NormaliseWinProcessPath(processPath);
      if(normalisedPath == target)
      {
        matchedPid = pid;
        break;
      }

      if(strlower(get_basename(processPath)) == targetBase)
      {
        SqcDiagLog(StringFormat::Fmt(
                       "[SQC-DIAG] RelaunchWait saw basename match pid=%u path='%s'\r\n", pid,
                       processPath.c_str())
                       .c_str());
      }
    } while(Process32Next(snapshot, &pe32));
  }

  CloseHandle(snapshot);
  return matchedPid;
}

static rdcpair<RDResult, uint32_t> WaitForRelaunchedProcessAndInject(
    const rdcstr &app, DWORD launchedPid, const rdcarray<EnvironmentModification> &env,
    const rdcstr &capturefile, const CaptureOptions &opts, DWORD timeoutMS)
{
  rdcarray<DWORD> attemptedPids;
  rdcarray<DWORD> seenPids;
  CaptureExistingProcessPIDs(seenPids);

  DWORD start = GetTickCount();
  rdcstr launchedPath;
  GetProcessImagePath(launchedPid, launchedPath);

  SqcDiagLog(StringFormat::Fmt(
                 "[SQC-DIAG] RelaunchWait BEGIN: tick=%u target='%s' launchedPid=%u launchedPath='%s' timeout=%u\r\n",
                 start, app.c_str(), launchedPid, launchedPath.c_str(), timeoutMS)
                 .c_str());

  while(GetTickCount() - start < timeoutMS)
  {
    DWORD pid = FindMatchingProcessByPath(app, launchedPid, attemptedPids, seenPids);
    if(pid != 0)
    {
      attemptedPids.push_back(pid);
      SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] RelaunchWait matched pid=%u\r\n", pid).c_str());

      Threading::Sleep(500);

      rdcpair<RDResult, uint32_t> ret =
          Process::InjectIntoProcess(pid, env, capturefile, opts, false);

      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] RelaunchWait inject pid=%u code=%d ident=%u msg='%s'\r\n", pid,
                     (int)ret.first.code, ret.second, ret.first.message.c_str())
                     .c_str());

      if(ret.first == ResultCode::Succeeded && ret.second != 0)
        return ret;
    }

    Threading::Sleep(250);
  }

  RDResult result = ResultCode::InjectionFailed;
  SET_ERROR_RESULT(result, ResultCode::InjectionFailed,
                   "Timed out waiting for relaunched process matching '%s'.", app.c_str());
  SqcDiagLog("[SQC-DIAG] RelaunchWait timeout\r\n");
  return {result, 0};
}

static bool IsLikelySteamLaunchTarget(const rdcstr &app)
{
  rdcstr normalised = NormaliseWinProcessPath(app);
  return normalised.contains("/steamapps/") || normalised.contains("\\steamapps\\");
}

rdcpair<RDResult, uint32_t> Process::LaunchWithD3D11Proxy(
    const rdcstr &app, const rdcstr &workingDir, const rdcstr &cmdLine,
    const rdcarray<EnvironmentModification> &env, const rdcstr &capturefile,
    const CaptureOptions &opts, bool waitForExit)
{
  RDResult result = ResultCode::Succeeded;

  SqcDiagLog(StringFormat::Fmt(
                 "[SQC-DIAG] D3D11Proxy BEGIN: tick=%u app='%s' workdir='%s' cmd='%s'\r\n",
                 GetTickCount(), app.c_str(), workingDir.c_str(), cmdLine.c_str())
                 .c_str());

  rdcstr targetProxy = SiblingPath(app, "d3d11.dll");
  bool targetExists =
      GetFileAttributesW(StringFormat::UTF82Wide(targetProxy).c_str()) != INVALID_FILE_ATTRIBUTES;
  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy target='%s' exists=%u\r\n",
                               targetProxy.c_str(), targetExists ? 1 : 0)
                 .c_str());

  if(targetExists && !IsSanQiD3D11ProxyPayload(targetProxy))
  {
    SET_ERROR_RESULT(result, ResultCode::FileIOFailed,
                     "D3D11 proxy launch refused because '%s' already exists.", targetProxy.c_str());
    SqcDiagLog("[SQC-DIAG] D3D11Proxy refused existing non-SanQi d3d11.dll\r\n");
    return {result, 0};
  }

  wchar_t systemLoadPath[MAX_PATH] = {};
  HMODULE selfModule = GetModuleHandleA(STRINGIZE(RDOC_BASE_NAME) ".dll");
  if(selfModule == NULL)
    selfModule = GetCachedSelfModuleHandle();
  GetModuleFileNameW(selfModule, systemLoadPath, MAX_PATH - 1);
  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy system_load='%s'\r\n",
                               StringFormat::Wide2UTF8(systemLoadPath).c_str())
                 .c_str());

  rdcstr proxySource = SiblingPath(StringFormat::Wide2UTF8(systemLoadPath), "d3d11_proxy.dll");
  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy source='%s'\r\n", proxySource.c_str())
                 .c_str());

  if(GetFileAttributesW(StringFormat::UTF82Wide(proxySource).c_str()) == INVALID_FILE_ATTRIBUTES)
  {
    SET_ERROR_RESULT(result, ResultCode::FileIOFailed,
                     "D3D11 proxy payload '%s' was not found. Build version_proxy first.",
                     proxySource.c_str());
    SqcDiagLog("[SQC-DIAG] D3D11Proxy source missing\r\n");
    return {result, 0};
  }

  if(!CopyFileW(StringFormat::UTF82Wide(proxySource).c_str(),
                StringFormat::UTF82Wide(targetProxy).c_str(), FALSE))
  {
    DWORD err = GetLastError();
    SET_ERROR_RESULT(result, ResultCode::FileIOFailed,
                     "Failed to copy D3D11 proxy payload to '%s' (err %u).", targetProxy.c_str(),
                     err);
    SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy copy failed err=%u\r\n", err).c_str());
    return {result, 0};
  }

  bool copied =
      GetFileAttributesW(StringFormat::UTF82Wide(targetProxy).c_str()) != INVALID_FILE_ATTRIBUTES;
  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy copy ok targetExistsAfterCopy=%u\r\n",
                               copied ? 1 : 0)
                 .c_str());

  rdcstr identFile = FileIO::GetTempFolderFilename();
  identFile += "/sqc_proxy_ident_";
  identFile += ToStr((uint64_t)GetTickCount());
  identFile += ".txt";
  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy ident='%s'\r\n", identFile.c_str()).c_str());

  rdcstr proxySystemLoad = StringFormat::Wide2UTF8(systemLoadPath);
  rdcstr targetSystemLoad = SiblingPath(app, "sqc_system_load.dll");
  if(CopyFileW(systemLoadPath, StringFormat::UTF82Wide(targetSystemLoad).c_str(), FALSE))
  {
    proxySystemLoad = targetSystemLoad;
    SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy local system_load='%s'\r\n",
                                 proxySystemLoad.c_str())
                   .c_str());
  }
  else
  {
    DWORD err = GetLastError();
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] D3D11Proxy local system_load copy failed err=%u path='%s'\r\n",
                   err, targetSystemLoad.c_str())
                   .c_str());
  }

  rdcarray<EnvironmentModification> proxyEnv = env;
  AddEnvMod(proxyEnv, "SQC_PROXY_SYSTEM_LOAD", proxySystemLoad);
  AddEnvMod(proxyEnv, "SQC_PROXY_CAPTURE_FILE", capturefile);
  AddEnvMod(proxyEnv, "SQC_PROXY_CAPTURE_OPTS", opts.EncodeAsString());
  AddEnvMod(proxyEnv, "SQC_PROXY_DEBUG_LOG", RDCGETLOGFILE());
  AddEnvMod(proxyEnv, "SQC_PROXY_IDENT_FILE", identFile);

  rdcstr proxyConfig = targetProxy + ".sqcproxy";
  rdcstr proxyConfigContents = StringFormat::Fmt("%s\n%s\n%s\n%s\n%s\n",
                                                 proxySystemLoad.c_str(), capturefile.c_str(),
                                                 opts.EncodeAsString().c_str(), RDCGETLOGFILE(),
                                                 identFile.c_str());
  if(FileIO::WriteAll(proxyConfig, proxyConfigContents))
  {
    SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy sidecar='%s'\r\n",
                                 proxyConfig.c_str())
                   .c_str());
  }
  else
  {
    SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy sidecar write failed path='%s'\r\n",
                                 proxyConfig.c_str())
                   .c_str());
  }

  PROCESS_INFORMATION pi = RunProcess(app, workingDir, cmdLine, proxyEnv, false, NULL, NULL);

  if(pi.dwProcessId == 0)
  {
    DeleteFileW(StringFormat::UTF82Wide(targetProxy).c_str());
    SET_ERROR_RESULT(result, ResultCode::InjectionFailed, "Failed to launch process.");
    SqcDiagLog("[SQC-DIAG] D3D11Proxy launch failed, target proxy deleted\r\n");
    return {result, 0};
  }

  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy launched pid=%u\r\n", pi.dwProcessId).c_str());

  ResumeThread(pi.hThread);

  uint32_t ident = 0;
  DWORD exitCode = STILL_ACTIVE;
  DWORD start = GetTickCount();
  DWORD proxyMissingSince = 0;
  while(GetTickCount() - start < 15000)
  {
    ident = ReadProxyIdent(identFile);
    if(ident != 0)
      break;

    if(GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode != STILL_ACTIVE)
      break;

    bool targetStillExists =
        GetFileAttributesW(StringFormat::UTF82Wide(targetProxy).c_str()) != INVALID_FILE_ATTRIBUTES;
    if(!targetStillExists)
    {
      DWORD now = GetTickCount();
      if(proxyMissingSince == 0)
      {
        proxyMissingSince = now;
        SqcDiagLog(StringFormat::Fmt(
                       "[SQC-DIAG] D3D11Proxy target removed while waiting tick=%u\r\n", now)
                       .c_str());
      }

      // If the game removes the proxy before it reports ident, the sideload path is gone.
      // Fall back quickly, before late anti-tamper startup makes direct injection less likely.
      if(now - proxyMissingSince >= 2000)
        break;
    }

    Sleep(100);
  }

  if(waitForExit)
    WaitForSingleObject(pi.hProcess, INFINITE);

  if(ident == 0)
  {
    rdcstr fallbackFailure;
    bool targetStillExists =
        GetFileAttributesW(StringFormat::UTF82Wide(targetProxy).c_str()) != INVALID_FILE_ATTRIBUTES;
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] D3D11Proxy no ident exitCode=%u targetStillExists=%u\r\n", exitCode,
                   targetStillExists ? 1 : 0)
                   .c_str());

    if(exitCode == STILL_ACTIVE)
    {
      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] D3D11Proxy fallback direct inject pid=%u\r\n",
                     pi.dwProcessId)
                     .c_str());

      rdcarray<EnvironmentModification> directEnv = env;
      AddYuanShenDirectEnv(directEnv);

      rdcpair<RDResult, uint32_t> direct =
          Process::InjectIntoProcess(pi.dwProcessId, directEnv, capturefile, opts, false);

      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] D3D11Proxy fallback direct result code=%d ident=%u msg='%s'\r\n",
                     (int)direct.first.code, direct.second, direct.first.message.c_str())
                     .c_str());

      if(direct.first == ResultCode::Succeeded && direct.second != 0)
      {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return direct;
      }

      fallbackFailure = direct.first.message;
      if(fallbackFailure.empty() && direct.first == ResultCode::Succeeded && direct.second == 0)
        fallbackFailure = "direct injection returned no target control ident";

      if(opts.hookIntoChildren)
      {
        rdcpair<RDResult, uint32_t> relaunched =
            WaitForRelaunchedProcessAndInject(app, pi.dwProcessId, directEnv, capturefile, opts,
                                              10000);

        if(relaunched.first == ResultCode::Succeeded && relaunched.second != 0)
        {
          CloseHandle(pi.hThread);
          CloseHandle(pi.hProcess);
          return relaunched;
        }

        if(!relaunched.first.message.empty())
          fallbackFailure = relaunched.first.message;
      }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if(!fallbackFailure.empty())
    {
      SET_ERROR_RESULT(result, ResultCode::InjectionFailed,
                       "D3D11 proxy launched the process but did not report target control. "
                       "Fallback injection also failed: %s",
                       fallbackFailure.c_str());
    }
    else
    {
      SET_ERROR_RESULT(result, ResultCode::InjectionFailed,
                       "D3D11 proxy launched the process but did not report target control.");
    }
    return {result, 0};
  }

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] D3D11Proxy SUCCESS ident=%u\r\n", ident).c_str());
  return {ResultCode::Succeeded, ident};
}

rdcpair<RDResult, uint32_t> Process::LaunchAndInjectIntoProcess(
    const rdcstr &app, const rdcstr &workingDir, const rdcstr &cmdLine,
    const rdcarray<EnvironmentModification> &env, const rdcstr &capturefile,
    const CaptureOptions &opts, bool waitForExit)
{
  if(WantsD3D11Proxy(env))
    return LaunchWithD3D11Proxy(app, workingDir, cmdLine, env, capturefile, opts, waitForExit);

  rdcarray<EnvironmentModification> launchEnv = env;
  if(IsYuanShenLaunchTarget(app) && !SqcLaunchEnvEnabled(launchEnv, "SQC_YUANSHEN_DIRECT_SYSTEM_LOAD"))
  {
    AddYuanShenDirectEnv(launchEnv);
    SqcDiagLog("[SQC-DIAG] YuanShen direct system_load launch env forced because D3D11 proxy is off\r\n");
  }

  if(IsYuanShenLaunchTarget(app) &&
     SqcLaunchEnvEnabled(launchEnv, "SQC_YUANSHEN_DIRECT_SYSTEM_LOAD"))
  {
    AddEnvMod(launchEnv, "SQC_DIRECT_CAPTURE_FILE", capturefile);
    AddEnvMod(launchEnv, "SQC_DIRECT_CAPTURE_OPTS", opts.EncodeAsString());
  }
  SqcDiagLogEnvState("launch", launchEnv);

  // Try cached proc address first (survives PE header wipe after stealth injection).
  // Tool processes (qrenderdoc etc.) skip CacheSelfModuleHandle in DllMain, so cache
  // may be empty — fall back to direct GetProcAddress which works when PE is intact.
  HMODULE mod = GetModuleHandleA(STRINGIZE(RDOC_BASE_NAME) ".dll");
  void *func = mod ? (void *)GetProcAddress(mod, "INTERNAL_SetCaptureFile") : NULL;

  if(func == NULL)
    func = (void *)GetCachedProcAddress("INTERNAL_SetCaptureFile");

  // diagnostic: log export lookup result
  {
    char diagBuf[256];
    wsprintfA(diagBuf, "[SQC-DIAG] LaunchAndInject: tick=%u func=%p\r\n",
              GetTickCount(), func);
    SqcDiagLog(diagBuf);
  }

  if(func == NULL)
  {
    const char *rdoc_dll = STRINGIZE(RDOC_BASE_NAME);
    RDResult result;
    SET_ERROR_RESULT(result, ResultCode::InternalError,
                     "Can't find required export function in %s.dll - corrupted/missing file?",
                     rdoc_dll);
    return {result, 0};
  }

  if(get_basename(app) == "explorer.exe" || get_basename(app) == "dllhost.exe")
  {
    RDResult result;
    SET_ERROR_RESULT(
        result, ResultCode::InjectionFailed,
        "For safety reasons SanQi Capture does not support capturing executables with a "
        "reserved system filename such as '%s'. Please rename your executable to capture.",
        get_basename(app).c_str());
    return {result, 0};
  }

  PROCESS_INFORMATION pi = RunProcess(app, workingDir, cmdLine, launchEnv, false, NULL, NULL);

  if(pi.dwProcessId == 0)
  {
    RDResult result;
    SET_ERROR_RESULT(result, ResultCode::InjectionFailed, "Failed to launch process.");
    return {result, 0};
  }

  const bool steamLaunchTarget = IsLikelySteamLaunchTarget(app);
  const bool yuanShenDirectTarget =
      IsYuanShenLaunchTarget(app) &&
      SqcLaunchEnvEnabled(launchEnv, "SQC_YUANSHEN_DIRECT_SYSTEM_LOAD");
  bool processResumed = false;

  if(steamLaunchTarget || (opts.hookIntoChildren && !yuanShenDirectTarget))
  {
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] ResumeThread before injection pid=%u steam=%u yuanshenDirect=%u hookChildren=%u\r\n",
                   pi.dwProcessId, steamLaunchTarget ? 1 : 0, yuanShenDirectTarget ? 1 : 0,
                   opts.hookIntoChildren ? 1 : 0)
                   .c_str());
    ResumeThread(pi.hThread);
    processResumed = true;
  }

  if(steamLaunchTarget)
  {
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] RelaunchWait steam target, waiting before first-process injection pid=%u hookChildren=%u\r\n",
                   pi.dwProcessId, opts.hookIntoChildren ? 1 : 0)
                   .c_str());

    rdcpair<RDResult, uint32_t> relaunched =
        WaitForRelaunchedProcessAndInject(app, pi.dwProcessId, launchEnv, capturefile, opts, 30000);

    if(relaunched.first == ResultCode::Succeeded && relaunched.second != 0)
    {
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      return relaunched;
    }

    DWORD firstExit = WaitForSingleObject(pi.hProcess, 0);
    if(firstExit == WAIT_TIMEOUT)
    {
      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] RelaunchWait fallback first process still alive, injecting pid=%u\r\n",
                     pi.dwProcessId)
                     .c_str());

      rdcpair<RDResult, uint32_t> first =
          InjectIntoProcess(pi.dwProcessId, launchEnv, capturefile, opts, false);

      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      return first;
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] RelaunchWait no relaunch and first process exited pid=%u exitCode=%u\r\n",
                   pi.dwProcessId, exitCode)
                   .c_str());

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return relaunched;
  }

  if(opts.hookIntoChildren && !yuanShenDirectTarget)
  {
    DWORD firstExit = WaitForSingleObject(pi.hProcess, 5000);
    if(firstExit == WAIT_OBJECT_0)
    {
      DWORD exitCode = 0;
      GetExitCodeProcess(pi.hProcess, &exitCode);
      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] RelaunchWait first process exited before injection pid=%u exitCode=%u\r\n",
                     pi.dwProcessId, exitCode)
                     .c_str());

      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);

      return WaitForRelaunchedProcessAndInject(app, pi.dwProcessId, launchEnv, capturefile, opts,
                                               30000);
    }

    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] RelaunchWait first process still alive, injecting pid=%u\r\n",
                   pi.dwProcessId)
                   .c_str());
  }

  HANDLE injectionCompleteEvent = NULL;
  HANDLE hooksReadyEvent = NULL;
  HANDLE hooksFailedEvent = NULL;
  DWORD injectionCompleteEventError = ERROR_SUCCESS;
  DWORD hooksReadyEventError = ERROR_SUCCESS;
  DWORD hooksFailedEventError = ERROR_SUCCESS;
  if(yuanShenDirectTarget)
  {
    wchar_t eventName[64] = {};
    SetLastError(ERROR_SUCCESS);
    swprintf_s(eventName, L"Local\\SQC_InjectComplete_%u", pi.dwProcessId);
    injectionCompleteEvent = CreateEventW(NULL, TRUE, FALSE, eventName);
    injectionCompleteEventError = GetLastError();
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] InjectionComplete event create pid=%u handle=%p err=%u\r\n",
                    pi.dwProcessId, injectionCompleteEvent, injectionCompleteEventError)
                   .c_str());

    SetLastError(ERROR_SUCCESS);
    swprintf_s(eventName, L"Local\\SQC_HooksReady_%u", pi.dwProcessId);
    hooksReadyEvent = CreateEventW(NULL, TRUE, FALSE, eventName);
    hooksReadyEventError = GetLastError();
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] HooksReady event create pid=%u handle=%p err=%u\r\n",
                   pi.dwProcessId, hooksReadyEvent, hooksReadyEventError)
                   .c_str());

    SetLastError(ERROR_SUCCESS);
    swprintf_s(eventName, L"Local\\SQC_HooksFailed_%u", pi.dwProcessId);
    hooksFailedEvent = CreateEventW(NULL, TRUE, FALSE, eventName);
    hooksFailedEventError = GetLastError();
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] HooksFailed event create pid=%u handle=%p err=%u\r\n",
                   pi.dwProcessId, hooksFailedEvent, hooksFailedEventError)
                   .c_str());

    const bool eventCreateFailed =
        injectionCompleteEvent == NULL || hooksReadyEvent == NULL || hooksFailedEvent == NULL ||
        injectionCompleteEventError == ERROR_ALREADY_EXISTS ||
        hooksReadyEventError == ERROR_ALREADY_EXISTS ||
        hooksFailedEventError == ERROR_ALREADY_EXISTS;
    if(eventCreateFailed)
    {
      RDResult result;
      SET_ERROR_RESULT(result, ResultCode::InjectionFailed,
                       "Failed to create hook coordination events for target process %u.",
                       pi.dwProcessId);

      SqcDiagLog(StringFormat::Fmt(
                     "[SQC-DIAG] Hook coordination event setup failed pid=%u errors=%u/%u/%u\r\n",
                     pi.dwProcessId, injectionCompleteEventError, hooksReadyEventError,
                     hooksFailedEventError)
                     .c_str());

      if(hooksFailedEvent != NULL)
        CloseHandle(hooksFailedEvent);
      if(hooksReadyEvent != NULL)
        CloseHandle(hooksReadyEvent);
      if(injectionCompleteEvent != NULL)
        CloseHandle(injectionCompleteEvent);

      // RunProcess created this process suspended. Do not leave an orphan if the handshake
      // cannot be established before injection.
      TerminateProcess(pi.hProcess, ERROR_INVALID_HANDLE);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return {result, 0};
    }
  }

  rdcpair<RDResult, uint32_t> ret =
      InjectIntoProcess(pi.dwProcessId, launchEnv, capturefile, opts, false);
  bool hookRegistrationReady = !yuanShenDirectTarget;

  if(hooksReadyEvent != NULL && hooksFailedEvent != NULL && ret.second != 0)
  {
    HANDLE hookStatusEvents[] = {hooksReadyEvent, hooksFailedEvent};
    DWORD hookStatus = WaitForMultipleObjects(ARRAY_COUNT(hookStatusEvents), hookStatusEvents,
                                              FALSE, 15000);
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] HookStatus wait pid=%u result=%u err=%u\r\n", pi.dwProcessId,
                   hookStatus, hookStatus == WAIT_FAILED ? GetLastError() : 0)
                   .c_str());

    if(hookStatus == WAIT_OBJECT_0 + 1)
    {
      SET_ERROR_RESULT(ret.first, ResultCode::InjectionFailed,
                       "Target process %u failed to register capture hooks.", pi.dwProcessId);
      TerminateProcess(pi.hProcess, ERROR_INVALID_FUNCTION);
    }
    else if(hookStatus != WAIT_OBJECT_0)
    {
      SET_ERROR_RESULT(ret.first, ResultCode::InjectionFailed,
                       "Timed out waiting for target process %u capture hooks.", pi.dwProcessId);
      TerminateProcess(pi.hProcess, WAIT_TIMEOUT);
    }
    else
    {
      uint32_t actualIdent = WaitForTargetIdentFile(pi.dwProcessId, pi.hProcess, 3000);
      if(actualIdent == 0)
      {
        SET_ERROR_RESULT(ret.first, ResultCode::InjectionFailed,
                         "Target process %u registered hooks but did not report target control.",
                         pi.dwProcessId);
        TerminateProcess(pi.hProcess, ERROR_INVALID_DATA);
      }
      else
      {
        ret.second = actualIdent;
        hookRegistrationReady = true;
        SqcDiagLog(StringFormat::Fmt(
                       "[SQC-DIAG] HookStatus actual target ident pid=%u ident=%u\r\n",
                       pi.dwProcessId, actualIdent)
                       .c_str());
      }
    }
  }
  else if(hooksReadyEvent != NULL && hooksFailedEvent != NULL)
  {
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] HookStatus wait skipped pid=%u ident=%u\r\n",
                   pi.dwProcessId, ret.second)
                   .c_str());
  }

  const bool canResume = !yuanShenDirectTarget ||
                         (hookRegistrationReady && ret.first == ResultCode::Succeeded &&
                          ret.second != 0);
  if(!processResumed && canResume)
  {
    DWORD previousSuspendCount = ResumeThread(pi.hThread);
    while(previousSuspendCount != DWORD(-1) && previousSuspendCount > 1)
      previousSuspendCount = ResumeThread(pi.hThread);

    if(previousSuspendCount == DWORD(-1))
    {
      DWORD resumeError = GetLastError();
      SET_ERROR_RESULT(ret.first, ResultCode::InjectionFailed,
                       "Failed to resume target process %u (err %u).", pi.dwProcessId,
                       resumeError);
      SqcDiagLog(StringFormat::Fmt(
                      "[SQC-DIAG] ResumeThread failed pid=%u err=%u\r\n", pi.dwProcessId,
                      resumeError)
                      .c_str());
      TerminateProcess(pi.hProcess, resumeError);
    }
    else
    {
      processResumed = true;
      SqcDiagLog(StringFormat::Fmt("[SQC-DIAG] ResumeThread succeeded pid=%u\r\n",
                                   pi.dwProcessId)
                     .c_str());
    }
  }
  else if(!processResumed && yuanShenDirectTarget)
  {
    SqcDiagLog(StringFormat::Fmt(
                   "[SQC-DIAG] Target kept suspended because hook setup failed pid=%u\r\n",
                   pi.dwProcessId)
                   .c_str());
    TerminateProcess(pi.hProcess, ERROR_INVALID_FUNCTION);
  }

  if(hooksFailedEvent != NULL)
    CloseHandle(hooksFailedEvent);
  if(hooksReadyEvent != NULL)
    CloseHandle(hooksReadyEvent);
  if(injectionCompleteEvent != NULL)
    CloseHandle(injectionCompleteEvent);

  CloseHandle(pi.hProcess);

  if(ret.second == 0 || ret.first != ResultCode::Succeeded)
  {
    CloseHandle(pi.hThread);
    return ret;
  }

  if(waitForExit)
    WaitForSingleObject(pi.hThread, INFINITE);

  CloseHandle(pi.hThread);

  return ret;
}

bool Process::CanGlobalHook()
{
  // all we need is admin rights and it's the caller's responsibility to ensure that.
  return true;
}

// to simplify the below code, rather than splitting by 32-bit/64-bit we split by native and Wow32.
// This means that for 32-bit code (whether it's on 32-bit OS or not) we just have native, and the
// Wow32 stuff is empty/unused. For 64-bit we use both. Thus the native registry key is always the
// same path regardless of the bitness we're running as and we don't have to move things around or
// have conditionals all over

struct GlobalHookData
{
  struct
  {
    HANDLE pipe = NULL;
    DWORD appinitEnabled = 0;
    rdcwstr appinitDLLs;
  } dataNative, dataWow32;

  int32_t finished = 0;
  Threading::ThreadHandle pipeThread = 0;
};

// utility function to close the registry keys, print an error, and quit
static RDResult HandleRegError(HKEY keyNative, HKEY keyWow32, LSTATUS ret, const char *msg)
{
  if(keyNative)
    RegCloseKey(keyNative);

  if(keyWow32)
    RegCloseKey(keyWow32);

  RDCLOG("Error with AppInit registry keys - %s (%d)", msg, ret);

  RETURN_ERROR_RESULT(ResultCode::InjectionFailed,
                      "Error updating registry to enable global hook.\n"
                      "Check that SanQi Capture is correctly running as administrator.");
}

#define REG_CHECK(msg)                                    \
  if(ret != ERROR_SUCCESS)                                \
  {                                                       \
    return HandleRegError(keyNative, keyWow32, ret, msg); \
  }

// function to backup the previous settings for AppInit, then enable it and write our own paths.
RDResult BackupAndChangeRegistry(GlobalHookData &hookdata, const rdcstr &shimpathWow32,
                                 const rdcstr &shimpathNative)
{
  HKEY keyNative = NULL;
  HKEY keyWow32 = NULL;

  // AppInit_DLLs requires short paths, but short paths can be disabled globally or on a per-volume
  // level. If short paths are disabled we'll get the long path back, we *always* expect the path to
  // get shorter because the shim filename is bigger than 8.3.

  DWORD nativeShortSize = GetShortPathNameW(StringFormat::UTF82Wide(shimpathNative).c_str(), NULL,
                                            (DWORD)shimpathNative.length());
  if(nativeShortSize == (DWORD)shimpathNative.length() + 1)
  {
    RETURN_ERROR_RESULT(
        ResultCode::FileIOFailed,
        "SanQi Capture is installed on a volume or system that has short paths disabled.\n"
        "For the global hook, short paths must be enabled where SanQi Capture is installed.");
  }

  if(!shimpathWow32.empty())
  {
    DWORD wow32ShortSize = GetShortPathNameW(StringFormat::UTF82Wide(shimpathWow32).c_str(), NULL,
                                             (DWORD)shimpathWow32.length());

    if(wow32ShortSize == (DWORD)shimpathWow32.length() + 1)
    {
      RETURN_ERROR_RESULT(
          ResultCode::FileIOFailed,
          "SanQi Capture is installed on a volume or system that has short paths disabled.\n"
          "For the global hook, short paths must be enabled where SanQi Capture is installed.");
    }
  }

  // open the native key
  LSTATUS ret = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, NULL,
                                0, KEY_READ | KEY_WRITE, NULL, &keyNative, NULL);

  REG_CHECK("Could not open AppInit key");

  // if we are doing Wow32, open that key as well
  if(!shimpathWow32.empty())
  {
    ret = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                          "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                          0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &keyWow32, NULL);

    REG_CHECK("Could not open AppInit key");
  }

  const DWORD one = 1;

  // fetch the previous data for LoadAppInit_DLLs and AppInit_DLLs
  DWORD sz = 4;
  ret = RegGetValueA(keyNative, NULL, "LoadAppInit_DLLs", RRF_RT_REG_DWORD, NULL,
                     (void *)&hookdata.dataNative.appinitEnabled, &sz);
  REG_CHECK("Could not fetch LoadAppInit_DLLs");

  sz = 0;
  ret = RegGetValueW(keyNative, NULL, L"AppInit_DLLs", RRF_RT_ANY, NULL, NULL, &sz);
  if(ret == ERROR_MORE_DATA || ret == ERROR_SUCCESS)
  {
    hookdata.dataNative.appinitDLLs = rdcwstr(sz / sizeof(wchar_t));
    ret = RegGetValueW(keyNative, NULL, L"AppInit_DLLs", RRF_RT_ANY, NULL,
                       hookdata.dataNative.appinitDLLs.data(), &sz);
  }
  REG_CHECK("Could not fetch AppInit_DLLs");

  // set DWORD:1 for LoadAppInit_DLLs and convert our path to a short path then set it
  ret = RegSetValueExA(keyNative, "LoadAppInit_DLLs", 0, REG_DWORD, (const BYTE *)&one, sizeof(one));
  REG_CHECK("Could not set LoadAppInit_DLLs");

  rdcwstr shortpath(shimpathNative.size());
  GetShortPathNameW(StringFormat::UTF82Wide(shimpathNative).c_str(), shortpath.data(),
                    (DWORD)shortpath.length());

  ret = RegSetValueExW(keyNative, L"AppInit_DLLs", 0, REG_SZ, (const BYTE *)shortpath.data(),
                       DWORD(shortpath.length() * sizeof(wchar_t)));
  REG_CHECK("Could not set AppInit_DLLs");

  // if we're doing Wow32, repeat the process for those keys
  if(keyWow32)
  {
    sz = 4;
    ret = RegGetValueA(keyWow32, NULL, "LoadAppInit_DLLs", RRF_RT_REG_DWORD, NULL,
                       (void *)&hookdata.dataWow32.appinitEnabled, &sz);
    REG_CHECK("Could not fetch LoadAppInit_DLLs");

    sz = 0;
    ret = RegGetValueW(keyWow32, NULL, L"AppInit_DLLs", RRF_RT_ANY, NULL, NULL, &sz);
    if(ret == ERROR_MORE_DATA || ret == ERROR_SUCCESS)
    {
      hookdata.dataWow32.appinitDLLs = rdcwstr(sz / sizeof(wchar_t));
      ret = RegGetValueW(keyWow32, NULL, L"AppInit_DLLs", RRF_RT_ANY, NULL,
                         hookdata.dataWow32.appinitDLLs.data(), &sz);
    }
    REG_CHECK("Could not fetch AppInit_DLLs");

    ret = RegSetValueExA(keyWow32, "LoadAppInit_DLLs", 0, REG_DWORD, (const BYTE *)&one, sizeof(one));
    REG_CHECK("Could not set LoadAppInit_DLLs");

    shortpath = rdcwstr(shimpathWow32.size());
    GetShortPathNameW(StringFormat::UTF82Wide(shimpathWow32).c_str(), shortpath.data(),
                      (DWORD)shortpath.length());

    ret = RegSetValueExW(keyWow32, L"AppInit_DLLs", 0, REG_SZ, (const BYTE *)shortpath.data(),
                         DWORD(shortpath.length() * sizeof(wchar_t)));
    REG_CHECK("Could not set AppInit_DLLs");
  }

  std::wstring backup;

  // write a .reg file that contains the previous settings, so that if all else fails the user can
  // manually insert it back into the registry to restore everything.
  backup += L"Windows Registry Editor Version 5.00\n";
  backup += L"\n";
  backup += L"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows]\n";
  backup += L"\"LoadAppInit_DLLs\"=dword:0000000";
  backup += (hookdata.dataNative.appinitEnabled ? L"1\n" : L"0\n");
  backup += L"\"AppInit_DLLs\"=\"";
  // we append with the C string so we don't add trailing NULLs into the text.
  backup += hookdata.dataNative.appinitDLLs.c_str();
  backup += L"\"\n";
  if(keyWow32)
  {
    backup += L"\n";
    backup +=
        L"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\"
        L"Windows NT\\CurrentVersion\\Windows]\n";
    backup += L"\"LoadAppInit_DLLs\"=dword:0000000";
    backup += (hookdata.dataWow32.appinitEnabled ? L"1\n" : L"0\n");
    backup += L"\"AppInit_DLLs\"=\"";
    backup += hookdata.dataWow32.appinitDLLs.c_str();
    backup += L"\"\n";
  }

  if(keyNative)
    RegCloseKey(keyNative);

  if(keyWow32)
    RegCloseKey(keyWow32);

  keyNative = keyWow32 = NULL;

  // write it to disk but don't fail if we can't, just print it to the log and keep going.
  wchar_t reg_backup[MAX_PATH];
  GetTempPathW(MAX_PATH, reg_backup);
  wcscat_s(reg_backup, L"SanQi_RestoreGlobalHook.reg");

  FILE *f = NULL;
  _wfopen_s(&f, reg_backup, L"w");
  if(f)
  {
    fputws(backup.c_str(), f);
    fclose(f);
  }
  else
  {
    RDCERR("Error opening registry backup file %ls", reg_backup);
    RDCERR("Backup registry data is:\n\n%ls\n\n", backup.c_str());
  }

  return RDResult();
}

// switch error-handling to print-and-continue, as we can't really do anything about it at this
// point and we want to continue restoring in case only one thing failed.
#undef REG_CHECK
#define REG_CHECK(msg)                                                      \
  if(ret != ERROR_SUCCESS)                                                  \
  {                                                                         \
    HandleRegError(keyNative, keyWow32, ret, "Could not open AppInit key"); \
  }

void RestoreRegistry(const GlobalHookData &hookdata)
{
  HKEY keyNative = NULL;
  HKEY keyWow32 = NULL;
  LSTATUS ret = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, NULL,
                                0, KEY_READ | KEY_WRITE, NULL, &keyNative, NULL);

  REG_CHECK("Could not open AppInit key");

#if ENABLED(RDOC_X64)
  ret = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0,
                        NULL, 0, KEY_READ | KEY_WRITE, NULL, &keyWow32, NULL);

  REG_CHECK("Could not open AppInit key");
#endif

  // set the native values back to where they were
  ret = RegSetValueExA(keyNative, "LoadAppInit_DLLs", 0, REG_DWORD,
                       (const BYTE *)&hookdata.dataNative.appinitEnabled,
                       sizeof(hookdata.dataNative.appinitEnabled));
  REG_CHECK("Could not set LoadAppInit_DLLs");

  ret = RegSetValueExW(keyNative, L"AppInit_DLLs", 0, REG_SZ,
                       (const BYTE *)hookdata.dataNative.appinitDLLs.c_str(),
                       DWORD(hookdata.dataNative.appinitDLLs.length() * sizeof(wchar_t)));
  REG_CHECK("Could not set AppInit_DLLs");

  // if we opened it, restore the Wow32 values as well
  if(keyWow32)
  {
    ret = RegSetValueExA(keyWow32, "LoadAppInit_DLLs", 0, REG_DWORD,
                         (const BYTE *)&hookdata.dataWow32.appinitEnabled,
                         sizeof(hookdata.dataWow32.appinitEnabled));
    REG_CHECK("Could not set LoadAppInit_DLLs");

    ret = RegSetValueExW(keyWow32, L"AppInit_DLLs", 0, REG_SZ,
                         (const BYTE *)hookdata.dataWow32.appinitDLLs.c_str(),
                         DWORD(hookdata.dataWow32.appinitDLLs.length() * sizeof(wchar_t)));
    REG_CHECK("Could not set AppInit_DLLs");
  }
}

static GlobalHookData *globalHook = NULL;

// a thread we run in the background just to keep the pipes open and wait until we're ready to stop
// the global hook.
static void GlobalHookThread()
{
  Threading::SetCurrentThreadName("GlobalHookThread");

  // keep looping doing an atomic compare-exchange to check that finished is still 0
  while(Atomic::CmpExch32(&globalHook->finished, 0, 0) == 0)
  {
    // wake every quarter of a second to test again
    Threading::Sleep(250);
  }

  char exitData[32] = "exit";

  // write some data into the pipe and close it. The data is (currently) unimportant, just that it
  // causes the blocking read on the other end to succeed and close the program.
  DWORD dummy = 0;
  if(globalHook->dataNative.pipe)
  {
    WriteFile(globalHook->dataNative.pipe, exitData, (DWORD)sizeof(exitData), &dummy, NULL);
    CloseHandle(globalHook->dataNative.pipe);
  }

  if(globalHook->dataWow32.pipe)
  {
    WriteFile(globalHook->dataWow32.pipe, exitData, (DWORD)sizeof(exitData), &dummy, NULL);
    CloseHandle(globalHook->dataWow32.pipe);
  }
}

RDResult Process::StartGlobalHook(const rdcstr &pathmatch, const rdcstr &capturefile,
                                  const CaptureOptions &opts)
{
  if(pathmatch.empty())
  {
    RETURN_ERROR_RESULT(ResultCode::InvalidParameter,
                        "Invalid global hook parameter, empty path to match");
  }

  rdcstr renderdocPath;
  FileIO::GetLibraryFilename(renderdocPath);

  renderdocPath = get_dirname(renderdocPath);

  // the native sanqicapture.exe is always next to the dll. Wow32 will be somewhere else
  rdcstr cmdpathNative = renderdocPath + "\\sanqicapture.exe";
  rdcstr cmdpathWow32;

  rdcstr shimpathNative =
  #if ENABLED(RDOC_X64)
      renderdocPath + "\\system_shim64.dll";
  #else
      renderdocPath + "\\system_shim32.dll";
  #endif
  rdcstr shimpathWow32;

#if ENABLED(RDOC_X64)

  // if it looks like we're in the development environment, look for the alternate bitness in the
  // corresponding folder
  int devLocation = renderdocPath.find("\\x64\\Development");
  if(devLocation >= 0)
  {
    renderdocPath.erase(devLocation, ~0U);

    shimpathWow32 = renderdocPath + "\\Win32\\Development\\system_shim32.dll";
    cmdpathWow32 = renderdocPath + "\\Win32\\Development\\sanqicapture.exe";
  }
  else
  {
    devLocation = renderdocPath.find("\\x64\\Release");

    if(devLocation >= 0)
    {
      renderdocPath.erase(devLocation, ~0U);

      shimpathWow32 = renderdocPath + "\\Win32\\Release\\system_shim32.dll";
      cmdpathWow32 = renderdocPath + "\\Win32\\Release\\sanqicapture.exe";
    }
  }

  // if we're not in the dev environment, assume it's under a x86\ subfolder
  if(devLocation < 0)
  {
    shimpathWow32 = renderdocPath + "\\x86\\system_shim32.dll";
    cmdpathWow32 = renderdocPath + "\\x86\\sanqicapture.exe";
  }

#else

  // nothing fancy to do here for 32-bit
  shimpathNative = renderdocPath + "\\system_shim32.dll";

#endif

  GlobalHookData hookdata;

  // try to backup and change the registry settings to start loading our shim dlls. If that fails,
  // we bail out immediately
  RDResult regStatus = BackupAndChangeRegistry(hookdata, shimpathWow32, shimpathNative);
  if(regStatus != ResultCode::Succeeded)
    return regStatus;

  PROCESS_INFORMATION pi = {0};
  STARTUPINFO si = {0};
  SECURITY_ATTRIBUTES pSec = {0};
  SECURITY_ATTRIBUTES tSec = {0};
  pSec.nLength = sizeof(pSec);
  tSec.nLength = sizeof(tSec);

  si.cb = sizeof(si);

  // serialise to string with two chars per byte
  rdcstr optstr = opts.EncodeAsString();
  rdcstr debugLogfile = RDCGETLOGFILE();

  rdcstr params = StringFormat::Fmt(
      "\"%s\" globalhook --match \"%s\" --capfile \"%s\" --debuglog \"%s\" --capopts \"%s\"",
      cmdpathNative.c_str(), pathmatch.c_str(), capturefile.c_str(), debugLogfile.c_str(),
      optstr.c_str());

  rdcwstr paramsAlloc = StringFormat::UTF82Wide(params);

  // we'll be setting stdin
  si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

  // hide the console window
  si.wShowWindow = SW_HIDE;

  // this is the end of the pipe that the child will inherit and use as stdin
  HANDLE childEnd = NULL;

  DWORD err;

  // create a pipe with the writing end for us, and the reading end as the child process's stdin
  {
    SECURITY_ATTRIBUTES pipeSec;
    pipeSec.nLength = sizeof(SECURITY_ATTRIBUTES);
    pipeSec.bInheritHandle = TRUE;
    pipeSec.lpSecurityDescriptor = NULL;

    BOOL res;
    res = CreatePipe(&childEnd, &hookdata.dataNative.pipe, &pipeSec, 0);

    if(!res)
    {
      err = GetLastError();
      RestoreRegistry(hookdata);
      RETURN_ERROR_RESULT(ResultCode::InternalError, "Could not create 32-bit stdin pipe (err %u)",
                          err);
    }

    // we don't want the child process to inherit our end
    res = SetHandleInformation(hookdata.dataNative.pipe, HANDLE_FLAG_INHERIT, 0);

    if(!res)
    {
      err = GetLastError();
      RestoreRegistry(hookdata);
      RETURN_ERROR_RESULT(ResultCode::InternalError,
                          "Could not make 32-bit stdin pipe inheritable (err %u)", err);
    }

    si.hStdInput = childEnd;
  }

  // launch the process
  BOOL retValue = CreateProcessW(NULL, &paramsAlloc[0], &pSec, &tSec, true, CREATE_NEW_CONSOLE,
                                 NULL, NULL, &si, &pi);

  err = GetLastError();

  // we don't need this end anymore, the child has it
  CloseHandle(childEnd);

  if(retValue == FALSE)
  {
    CloseHandle(hookdata.dataNative.pipe);
    RestoreRegistry(hookdata);
    RETURN_ERROR_RESULT(ResultCode::InternalError, "Can't launch sanqicapture from '%s' (err %u)",
                        cmdpathNative.c_str(), err);
  }

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  RDCEraseEl(pi);

// repeat the process for the Wow32 sanqicapture
#if ENABLED(RDOC_X64)
  params = StringFormat::Fmt(
      "\"%s\" globalhook --match \"%s\" --capfile \"%s\" --debuglog \"%s\" --capopts \"%s\"",
      cmdpathWow32.c_str(), pathmatch.c_str(), capturefile.c_str(), debugLogfile.c_str(),
      optstr.c_str());

  paramsAlloc = StringFormat::UTF82Wide(params);

  {
    SECURITY_ATTRIBUTES pipeSec;
    pipeSec.nLength = sizeof(SECURITY_ATTRIBUTES);
    pipeSec.bInheritHandle = TRUE;
    pipeSec.lpSecurityDescriptor = NULL;

    BOOL res;
    res = CreatePipe(&childEnd, &hookdata.dataWow32.pipe, &pipeSec, 0);

    if(!res)
    {
      err = GetLastError();
      RestoreRegistry(hookdata);
      RETURN_ERROR_RESULT(ResultCode::InternalError, "Could not create 64-bit stdin pipe (err %u)",
                          err);
    }

    res = SetHandleInformation(hookdata.dataWow32.pipe, HANDLE_FLAG_INHERIT, 0);

    if(!res)
    {
      err = GetLastError();
      RestoreRegistry(hookdata);
      RETURN_ERROR_RESULT(ResultCode::InternalError,
                          "Could not make 64-bit stdin pipe inheritable (err %u)", err);
    }

    si.hStdInput = childEnd;
  }

  retValue = CreateProcessW(NULL, &paramsAlloc[0], &pSec, &tSec, true, CREATE_NEW_CONSOLE, NULL,
                            NULL, &si, &pi);

  err = GetLastError();

  // we don't need this end anymore
  CloseHandle(childEnd);

  if(retValue == FALSE)
  {
    CloseHandle(hookdata.dataNative.pipe);
    CloseHandle(hookdata.dataWow32.pipe);
    RestoreRegistry(hookdata);
    RETURN_ERROR_RESULT(ResultCode::InternalError, "Can't launch sanqicapture from '%s' (err %u)",
                        cmdpathWow32.c_str(), err);
  }

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
#endif

  // set static global pointer with our data, and launch the thread
  globalHook = new GlobalHookData;
  *globalHook = hookdata;

  globalHook->pipeThread = Threading::CreateThread(&GlobalHookThread);

  return RDResult();
}

bool Process::IsGlobalHookActive()
{
  return globalHook != NULL;
}
void Process::StopGlobalHook()
{
  if(!globalHook)
    return;

  // set the finished flag and join to the thread so it closes the pipes (and so the child
  // processes)
  Atomic::Inc32(&globalHook->finished);

  Threading::JoinThread(globalHook->pipeThread);
  Threading::CloseThread(globalHook->pipeThread);

  // restore the registry settings from before we started
  RestoreRegistry(*globalHook);

  delete globalHook;
  globalHook = NULL;
}

bool Process::IsModuleLoaded(const rdcstr &module)
{
  return GetModuleHandleA(module.c_str()) != NULL;
}

void *Process::LoadModule(const rdcstr &module)
{
  HMODULE mod = GetModuleHandleA(module.c_str());
  if(mod != NULL)
    return mod;

  return LoadLibraryA(module.c_str());
}

void *Process::GetFunctionAddress(void *module, const rdcstr &function)
{
  if(module == NULL)
    return NULL;

  return (void *)GetProcAddress((HMODULE)module, function.c_str());
}

uint32_t Process::GetCurrentPID()
{
  return (uint32_t)GetCurrentProcessId();
}

void Process::Shutdown()
{
  // nothing to do
}
