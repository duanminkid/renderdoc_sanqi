/******************************************************************************
 * Android Stealth Hooks — /proc/self/maps and dl_iterate_phdr filtering
 *
 * Hooks open/openat/read to filter our library from /proc/self/maps,
 * and hooks dl_iterate_phdr to hide our DSO from enumeration.
 *
 * This file provides the hook functions. They must be installed by the
 * PLT hooking infrastructure in android_hook.cpp.
 *
 * Call InstallAndroidStealthHooks() after PLT hooks are set up.
 ******************************************************************************/

#pragma once

#if defined(__linux__) || defined(__ANDROID__)

#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <link.h>
#include <sys/mman.h>
#include <errno.h>

#include "posix_stealth.h"

// ============================================================================
// /proc/self/maps filtering via fd tracking
// ============================================================================

// Track fds that point to /proc/self/maps so we can filter reads
static int g_MapsFilterFd = -1;
static char *g_FilteredMaps = NULL;
static size_t g_FilteredMapsLen = 0;
static size_t g_FilteredMapsPos = 0;

// Original function pointers (set by PLT hooking)
typedef int (*pfn_open)(const char *pathname, int flags, ...);
typedef int (*pfn_openat)(int dirfd, const char *pathname, int flags, ...);
typedef ssize_t (*pfn_read)(int fd, void *buf, size_t count);
typedef int (*pfn_close)(int fd);
typedef int (*pfn_dl_iterate_phdr)(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data);

static pfn_open g_real_open = NULL;
static pfn_openat g_real_openat = NULL;
static pfn_read g_real_read = NULL;
static pfn_close g_real_close = NULL;
static pfn_dl_iterate_phdr g_real_dl_iterate_phdr = NULL;

static bool IsProcSelfMaps(const char *path)
{
  if(!path) return false;
  return (strcmp(path, "/proc/self/maps") == 0 ||
          strcmp(path, "/proc/self/smaps") == 0);
}

// ============================================================================
// Hooked open()
// ============================================================================
static int Hook_open(const char *pathname, int flags, ...)
{
  // Get variadic mode_t argument if O_CREAT
  mode_t mode = 0;
  if(flags & O_CREAT)
  {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }

  if(!g_real_open)
  {
    g_real_open = (pfn_open)dlsym(RTLD_NEXT, "open");
    if(!g_real_open) return -1;
  }

  int fd = (flags & O_CREAT) ? g_real_open(pathname, flags, mode) : g_real_open(pathname, flags);

  if(fd >= 0 && IsProcSelfMaps(pathname))
  {
    // Prepare filtered content for this fd
    if(g_FilteredMaps)
    {
      free(g_FilteredMaps);
      g_FilteredMaps = NULL;
    }
    g_FilteredMaps = GetFilteredProcMaps(&g_FilteredMapsLen);
    g_FilteredMapsPos = 0;
    g_MapsFilterFd = fd;
  }

  return fd;
}

// ============================================================================
// Hooked openat()
// ============================================================================
static int Hook_openat(int dirfd, const char *pathname, int flags, ...)
{
  mode_t mode = 0;
  if(flags & O_CREAT)
  {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }

  if(!g_real_openat)
  {
    g_real_openat = (pfn_openat)dlsym(RTLD_NEXT, "openat");
    if(!g_real_openat) return -1;
  }

  int fd = (flags & O_CREAT) ? g_real_openat(dirfd, pathname, flags, mode) :
                                g_real_openat(dirfd, pathname, flags);

  if(fd >= 0 && IsProcSelfMaps(pathname))
  {
    if(g_FilteredMaps)
    {
      free(g_FilteredMaps);
      g_FilteredMaps = NULL;
    }
    g_FilteredMaps = GetFilteredProcMaps(&g_FilteredMapsLen);
    g_FilteredMapsPos = 0;
    g_MapsFilterFd = fd;
  }

  return fd;
}

// ============================================================================
// Hooked read() — returns filtered content for /proc/self/maps fds
// ============================================================================
static ssize_t Hook_read(int fd, void *buf, size_t count)
{
  if(!g_real_read)
  {
    g_real_read = (pfn_read)dlsym(RTLD_NEXT, "read");
    if(!g_real_read) return -1;
  }

  if(fd == g_MapsFilterFd && g_FilteredMaps && fd >= 0)
  {
    // Serve from filtered buffer
    size_t remaining = g_FilteredMapsLen - g_FilteredMapsPos;
    if(remaining == 0) return 0;    // EOF
    size_t toRead = (count < remaining) ? count : remaining;
    memcpy(buf, g_FilteredMaps + g_FilteredMapsPos, toRead);
    g_FilteredMapsPos += toRead;
    return (ssize_t)toRead;
  }

  return g_real_read(fd, buf, count);
}

// ============================================================================
// Hooked close() — cleanup filtered maps tracking
// ============================================================================
static int Hook_close(int fd)
{
  if(!g_real_close)
  {
    g_real_close = (pfn_close)dlsym(RTLD_NEXT, "close");
    if(!g_real_close) return -1;
  }

  if(fd == g_MapsFilterFd && fd >= 0)
  {
    g_MapsFilterFd = -1;
    if(g_FilteredMaps)
    {
      free(g_FilteredMaps);
      g_FilteredMaps = NULL;
    }
    g_FilteredMapsLen = 0;
    g_FilteredMapsPos = 0;
  }

  return g_real_close(fd);
}

// ============================================================================
// dl_iterate_phdr filtering — hide our DSO from enumeration
// ============================================================================

struct DlIterateFilterData {
  int (*real_callback)(struct dl_phdr_info *, size_t, void *);
  void *real_data;
};

static int FilteredDlIterateCallback(struct dl_phdr_info *info, size_t size, void *data)
{
  DlIterateFilterData *filterData = (DlIterateFilterData *)data;

  // Check if this DSO is one we should hide
  if(info && info->dlpi_name)
  {
    if(LineContainsHiddenLib(info->dlpi_name))
      return 0;    // Skip this entry, continue iteration
  }

  // Pass through to real callback
  return filterData->real_callback(info, size, filterData->real_data);
}

static int Hook_dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data)
{
  if(!g_real_dl_iterate_phdr)
  {
    g_real_dl_iterate_phdr = (pfn_dl_iterate_phdr)dlsym(RTLD_NEXT, "dl_iterate_phdr");
    if(!g_real_dl_iterate_phdr) return -1;
  }

  DlIterateFilterData filterData;
  filterData.real_callback = callback;
  filterData.real_data = data;

  return g_real_dl_iterate_phdr(FilteredDlIterateCallback, &filterData);
}

// ============================================================================
// Public API — to be called after PLT hook infrastructure is ready
// ============================================================================

// These function pointers can be registered with the PLT hooking system.
// The caller should use plthook_replace to install them on target libraries.
struct AndroidStealthHooks {
  void *hook_open;
  void *hook_openat;
  void *hook_read;
  void *hook_close;
  void *hook_dl_iterate_phdr;
};

static AndroidStealthHooks GetAndroidStealthHooks()
{
  AndroidStealthHooks hooks;
  hooks.hook_open = (void *)&Hook_open;
  hooks.hook_openat = (void *)&Hook_openat;
  hooks.hook_read = (void *)&Hook_read;
  hooks.hook_close = (void *)&Hook_close;
  hooks.hook_dl_iterate_phdr = (void *)&Hook_dl_iterate_phdr;
  return hooks;
}

#endif // __linux__ || __ANDROID__
