/******************************************************************************
 * Hook Log Helper
 *
 * Provides dual output to both debug stream and log file
 ******************************************************************************/

#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

// Enable/Disable hook logging for stealth
// Set to 0 for release builds to avoid detection
#ifndef ENABLE_HOOK_LOGGING
  // ENABLED for debugging - set to 0 for release/stealth builds
  // Log output goes to: %TEMP%\system_load_hook.log + OutputDebugString
  #define ENABLE_HOOK_LOGGING 1
#endif

// Accessor function for the global log file pointer
// This avoids linker issues with multiple projects
inline FILE** GetHookLogFilePtr()
{
  static FILE* s_HookLogFile = NULL;
  return &s_HookLogFile;
}

#if ENABLE_HOOK_LOGGING
// Dual output: Debug string (for DebugView) + File
inline void HookLog(const char *fmt, ...)
{
  char buffer[2048];
  va_list args;

  // Format the message
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer) - 1, fmt, args);
  va_end(args);
  buffer[sizeof(buffer) - 1] = '\0';

  // 1. Output to debug stream (visible in DebugView)
  OutputDebugStringA("[HOOK_LOG] ");
  OutputDebugStringA(buffer);

  // 2. Output to console (if available)
  printf("%s", buffer);
  fflush(stdout);

  // 3. Output to log file
  FILE** ppFile = GetHookLogFilePtr();
  if(!*ppFile)
  {
    // Create log file in TEMP directory (first time only)
    char logPath[MAX_PATH];
    GetTempPathA(MAX_PATH, logPath);
    strcat_s(logPath, MAX_PATH, "system_load_hook.log");
    fopen_s(ppFile, logPath, "a");

    if(*ppFile)
    {
      fprintf(*ppFile, "=== HOOK LOG STARTED ===\n");
      fflush(*ppFile);
    }
  }

  if(*ppFile)
  {
    fprintf(*ppFile, "%s", buffer);
    fflush(*ppFile);
  }
}

// Convenience macro
#define HOOK_LOG(...) HookLog(__VA_ARGS__)
#else
// Stealth mode: disable all logging
#define HOOK_LOG(...) ((void)0)
#endif
