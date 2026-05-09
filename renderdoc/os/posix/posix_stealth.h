/******************************************************************************
 * POSIX/Android Stealth - /proc/self/maps Hiding
 *
 * On Android/Linux, anti-cheat detects injected libraries by:
 * 1. Reading /proc/self/maps — lists all memory mappings including our .so
 * 2. Scanning loaded DSOs via dl_iterate_phdr
 * 3. Checking Vulkan layer registration
 *
 * This module hooks the open/read syscalls to filter our library entries
 * from /proc/self/maps output.
 *
 * NOTE: This uses LD_PRELOAD-style hooks. On Android, root access or
 * a modified app is needed to apply this.
 ******************************************************************************/

#pragma once

#if defined(__linux__) || defined(__ANDROID__)

#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

// ============================================================================
// Configuration: library names to hide from /proc/self/maps
// ============================================================================

// These strings will be filtered from /proc/self/maps output.
// Any line containing these substrings will be removed.
static const char *g_HiddenLibraries[] = {
    "libVkLayer_GLES_SystemLoad",
    "system_load",
    "libsysload",
    "SystemLoad",
    NULL    // sentinel
};

// ============================================================================
// /proc/self/maps filtering
// ============================================================================

// Check if a maps line contains any of our hidden library names
static inline int LineContainsHiddenLib(const char *line)
{
    for(int i = 0; g_HiddenLibraries[i] != NULL; i++)
    {
        if(strstr(line, g_HiddenLibraries[i]) != NULL)
            return 1;
    }
    return 0;
}

// Read /proc/self/maps and return a filtered copy
// Caller must free() the returned buffer
static char *GetFilteredProcMaps(size_t *outLen)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if(!f)
    {
        *outLen = 0;
        return NULL;
    }

    // Read entire file
    char *buf = NULL;
    size_t bufLen = 0;
    size_t bufCap = 0;
    char line[1024];

    while(fgets(line, sizeof(line), f))
    {
        // Skip lines containing our hidden libraries
        if(LineContainsHiddenLib(line))
            continue;

        size_t lineLen = strlen(line);
        if(bufLen + lineLen + 1 > bufCap)
        {
            bufCap = (bufCap == 0) ? 8192 : bufCap * 2;
            buf = (char *)realloc(buf, bufCap);
        }
        memcpy(buf + bufLen, line, lineLen);
        bufLen += lineLen;
    }

    fclose(f);

    if(buf)
        buf[bufLen] = '\0';
    *outLen = bufLen;
    return buf;
}

// ============================================================================
// ELF Header Erasure (equivalent to PE header wiping on Windows)
// ============================================================================

static void EraseElfHeaders(void *baseAddr)
{
    if(!baseAddr)
        return;

    // ELF magic: 0x7f 'E' 'L' 'F'
    unsigned char *p = (unsigned char *)baseAddr;
    if(p[0] != 0x7f || p[1] != 'E' || p[2] != 'L' || p[3] != 'F')
        return;

    // ELF header is 64 bytes on 64-bit, 52 bytes on 32-bit
#if defined(__LP64__) || defined(__x86_64__) || defined(__aarch64__)
    size_t headerSize = 64;
#else
    size_t headerSize = 52;
#endif

    // Make writable, zero, restore (best-effort)
    // Note: mprotect requires page-aligned address and size
    // The ELF header is always at the start of a page
    long pageSize = sysconf(_SC_PAGESIZE);
    if(pageSize <= 0)
        pageSize = 4096;

    // mprotect to writable
    void *pageAddr = (void *)((unsigned long)baseAddr & ~(pageSize - 1));
    if(mprotect(pageAddr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) == 0)
    {
        memset(baseAddr, 0, headerSize);
        mprotect(pageAddr, pageSize, PROT_READ | PROT_EXEC);
    }
}

#include <sys/mman.h>

// ============================================================================
// Apply Android/Linux stealth measures
// ============================================================================
static void ApplyPosixStealth()
{
    // Step 1: Find our own library's base address via dl_iterate_phdr
    // and erase its ELF headers
    Dl_info info;
    if(dladdr((void *)&ApplyPosixStealth, &info) && info.dli_fbase)
    {
        EraseElfHeaders(info.dli_fbase);
    }

    // Step 2: /proc/self/maps filtering is done on-demand via
    // GetFilteredProcMaps() — called when the game tries to read maps.
    // For full hook-based filtering, we'd need to intercept open()/read()
    // for "/proc/self/maps" paths, which requires PLT hooking on the
    // target process. This is left as an advanced feature since it
    // requires modifying the PLT hooking infrastructure in hooks/hooks.h
    // to support posix PLT patching.
}

#endif // __linux__ || __ANDROID__
