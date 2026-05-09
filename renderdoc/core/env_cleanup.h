/******************************************************************************
 * Environment Cleanup & Thread Name Disguise
 *
 * After injection, clean up all environment variables and thread names
 * that could reveal our presence to anti-cheat scanning.
 ******************************************************************************/

#pragma once

// ============================================================================
// Windows Implementation
// ============================================================================
#if defined(_WIN32)

#include <windows.h>
#include <string.h>

// Environment variables to clear after injection
static const wchar_t *g_EnvVarsToClean[] = {
    L"GC_CAPFILE",
    L"GC_CAPOPTS",
    L"GC_DEBUG_LOG_FILE",
    L"ENABLE_VULKAN_GC_CAPTURE",
    L"ENABLE_VULKAN_SQC_LAYER_ACTIVATE_",
    L"SL_HOOK_PID",
    L"VK_LAYER_PATH",
    L"VK_INSTANCE_LAYERS",
    L"DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1",
    NULL
};

static void CleanEnvironmentVariables()
{
  for(int i = 0; g_EnvVarsToClean[i] != NULL; i++)
  {
    SetEnvironmentVariableW(g_EnvVarsToClean[i], NULL);    // Delete the variable
  }
}

// Rename our threads to look like system threads
static void DisguiseThreadName(HANDLE hThread)
{
  // SetThreadDescription available on Windows 10 1607+
  typedef HRESULT(WINAPI *pfnSetThreadDescription)(HANDLE, PCWSTR);
  static pfnSetThreadDescription fnSet = NULL;
  static bool resolved = false;

  if(!resolved)
  {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if(hKernel)
      fnSet = (pfnSetThreadDescription)GetProcAddress(hKernel, "SetThreadDescription");
    resolved = true;
  }

  if(fnSet)
  {
    // Use a benign system-like name
    fnSet(hThread, L"win32u");
  }
}

// Disguise current thread
static void DisguiseCurrentThread()
{
  DisguiseThreadName(GetCurrentThread());
}

// ============================================================================
// POSIX/Android Implementation
// ============================================================================
#elif defined(__linux__) || defined(__ANDROID__)

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/prctl.h>

static const char *g_PosixEnvVarsToClean[] = {
    "GC_CAPFILE",
    "GC_CAPOPTS",
    "GC_DEBUG_LOG_FILE",
    "ENABLE_VULKAN_GC_CAPTURE",
    "ENABLE_VULKAN_SQC_LAYER_ACTIVATE_",
    "SL_HOOK_PID",
    "VK_LAYER_PATH",
    "VK_INSTANCE_LAYERS",
    "LD_PRELOAD",
    NULL
};

static void CleanEnvironmentVariables()
{
  for(int i = 0; g_PosixEnvVarsToClean[i] != NULL; i++)
  {
    unsetenv(g_PosixEnvVarsToClean[i]);
  }
}

static void DisguiseCurrentThread()
{
  // Set thread name to something innocuous
  prctl(PR_SET_NAME, "binder:worker", 0, 0, 0);
}

#endif
