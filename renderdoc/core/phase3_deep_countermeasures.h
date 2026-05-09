/******************************************************************************
 * Phase 3 — Deep Anti-Cheat Countermeasures
 *
 * Design Document for advanced stealth features.
 * These require dedicated build environments and extensive testing.
 ******************************************************************************/

#pragma once

// ============================================================================
// 3.1 Kernel Driver Auxiliary (Windows — TitanHide-style)
// ============================================================================
//
// PURPOSE: Intercept kernel callbacks that anti-cheat drivers use to detect us.
//
// TARGET CALLBACKS TO NEUTRALIZE:
//   - ObRegisterCallbacks: Strips PROCESS_VM_WRITE from handle access masks
//     so anti-cheat can't prevent our VirtualAllocEx/WriteProcessMemory.
//   - PsSetCreateThreadNotifyRoutine: Filters notifications about our threads.
//   - PsSetLoadImageNotifyRoutine: Filters notifications about our DLL loads.
//   - MmVerifyCallbackFunction: Prevents integrity checks on our hooks.
//
// IMPLEMENTATION APPROACH:
//   1. Load a signed kernel driver (requires EV cert or test signing)
//   2. Driver hooks the above callbacks via DKOM or filter registration
//   3. User-mode component (our DLL) communicates via IOCTL to register
//      which PIDs/modules to hide
//
// REFERENCE PROJECTS:
//   - TitanHide (https://github.com/mrexodia/TitanHide)
//   - Blackbone (https://github.com/DarthTon/Blackbone)
//
// FILES TO CREATE:
//   renderdoc/os/win32/driver/stealth_driver.sys  (kernel driver)
//   renderdoc/os/win32/driver/stealth_driver.h    (shared IOCTL defs)
//   renderdoc/os/win32/driver/stealth_client.h    (user-mode loader)

// ============================================================================
// 3.2 Shamiko/MagiskHide Integration (Android)
// ============================================================================
//
// PURPOSE: Hide root status and Magisk presence from anti-cheat.
//
// APPROACH:
//   1. Ensure Shamiko module is installed alongside our Zygisk module
//   2. Add our target packages to Magisk DenyList
//   3. Our Zygisk module checks Process::isOnDenyList and acts accordingly
//   4. Hide Magisk-specific artifacts:
//      - /data/adb/magisk
//      - magiskd process
//      - su binary paths
//      - SELinux context modifications
//
// INTEGRATION POINTS:
//   - zygisk_module/main.cpp: Check StateFlag::PROCESS_ON_DENYLIST
//   - android_stealth_hooks.h: Filter /proc/self/mounts for magisk tmpfs

// ============================================================================
// 3.3 Syscall-Level Hooks (Windows + Android)
// ============================================================================
//
// PURPOSE: Bypass user-mode integrity checks by hooking at syscall level.
//
// WINDOWS APPROACH:
//   Anti-cheat may verify ntdll function prologues haven't been patched.
//   Instead of inline-hooking ntdll, we can:
//   1. Map a fresh copy of ntdll.dll from disk
//   2. Redirect our calls to the clean copy
//   3. Or use direct syscall stubs (syscall number + SYSCALL instruction)
//
// ANDROID APPROACH:
//   Use seccomp BPF filters or ptrace to intercept syscalls.
//   Or patch vDSO/vsyscall pages.
//
// REFERENCE:
//   - SyscallDumper for extracting syscall numbers
//   - Hell's Gate / Halo's Gate techniques for dynamic syscall resolution
//
// IMPLEMENTATION SKELETON:

#ifdef _WIN32
#include <windows.h>

// Direct syscall stub for NtQueryVirtualMemory
// Avoids touching ntdll.dll code at all
typedef struct _DIRECT_SYSCALL {
    DWORD syscallNumber;
    BYTE  stub[32];    // Contains: mov r10, rcx; mov eax, <num>; syscall; ret
} DIRECT_SYSCALL;

// Resolve syscall number at runtime from clean ntdll
static DWORD ResolveSyscallNumber(const char *funcName)
{
    // Map clean ntdll from disk
    wchar_t ntdllPath[MAX_PATH];
    GetSystemDirectoryW(ntdllPath, MAX_PATH);
    wcscat_s(ntdllPath, MAX_PATH, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if(!hMap) return 0;

    PVOID pBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if(!pBase) return 0;

    // Find export in clean mapping
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)pBase + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)pBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD *)((BYTE *)pBase + pExport->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)pBase + pExport->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)((BYTE *)pBase + pExport->AddressOfFunctions);

    DWORD syscallNum = 0;
    for(DWORD i = 0; i < pExport->NumberOfNames; i++)
    {
        const char *name = (const char *)((BYTE *)pBase + names[i]);
        if(strcmp(name, funcName) == 0)
        {
            BYTE *funcAddr = (BYTE *)pBase + funcs[ordinals[i]];
            // x64 syscall stub: mov r10, rcx (49 89 CA) ; mov eax, <num> (B8 xx xx 00 00)
            if(funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1 &&
               funcAddr[3] == 0xB8)
            {
                syscallNum = *(DWORD *)(funcAddr + 4);
            }
            break;
        }
    }

    UnmapViewOfFile(pBase);
    return syscallNum;
}

#endif // _WIN32

// ============================================================================
// 3.4 Code Integrity Bypass
// ============================================================================
//
// PURPOSE: Prevent anti-cheat from detecting our inline hooks by
//          maintaining checksums of original code pages.
//
// APPROACH (Windows):
//   1. Before installing inline hooks, save original page checksums
//   2. Hook NtQueryVirtualMemory for MemoryWorkingSetExInformation
//   3. When anti-cheat reads our hooked pages via ReadProcessMemory,
//      return the original unhooked bytes (copy-on-read)
//   4. Use VEH (Vectored Exception Handler) with PAGE_GUARD to detect
//      integrity scans and serve clean pages
//
// APPROACH (Android):
//   1. Use inotify to detect reads of /proc/self/mem
//   2. mprotect pages with PROT_NONE + SIGSEGV handler to detect scans
//   3. Serve clean page contents when scan is detected
