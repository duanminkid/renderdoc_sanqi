/******************************************************************************
 * NtQuery Hook - Memory Region & Module Hiding
 *
 * Hooks NtQueryVirtualMemory and NtQuerySystemInformation via IAT patching
 * to hide our DLL's memory regions from anti-cheat enumeration.
 *
 * Detection vectors blocked:
 *   - NtQueryVirtualMemory(MemoryBasicInformation) → hides our pages
 *   - NtQueryVirtualMemory(MemoryMappedFilenameInformation) → hides our path
 *   - NtQuerySystemInformation(SystemModuleInformation) → hides from driver queries
 *
 * Call InstallNtQueryHooks() AFTER hooks are installed but BEFORE PEB unlink.
 ******************************************************************************/

#pragma once

#include <windows.h>

// ============================================================================
// Stored module range for self-identification
// ============================================================================
static PVOID g_OurModuleBase = NULL;
static SIZE_T g_OurModuleSize = 0;

// ============================================================================
// NtQueryVirtualMemory hook
// ============================================================================

// Typedef matching ntdll!NtQueryVirtualMemory signature
typedef LONG(NTAPI *pfnNtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    int MemoryInformationClass,    // MEMORY_INFORMATION_CLASS
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength);

static pfnNtQueryVirtualMemory g_OrigNtQueryVirtualMemory = NULL;

// Memory information classes we care about
#define MemoryBasicInformation_             0
#define MemoryMappedFilenameInformation_    2

static LONG NTAPI Hook_NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    int MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength)
{
  LONG status = g_OrigNtQueryVirtualMemory(ProcessHandle, BaseAddress,
                                            MemoryInformationClass,
                                            MemoryInformation,
                                            MemoryInformationLength,
                                            ReturnLength);

  // Only filter queries about our own process
  if(ProcessHandle != GetCurrentProcess() && ProcessHandle != (HANDLE)-1)
    return status;

  // STATUS_SUCCESS = 0
  if(status != 0)
    return status;

  // Check if the queried address falls within our module
  ULONG_PTR queryAddr = (ULONG_PTR)BaseAddress;
  ULONG_PTR ourStart = (ULONG_PTR)g_OurModuleBase;
  ULONG_PTR ourEnd = ourStart + g_OurModuleSize;

  if(queryAddr >= ourStart && queryAddr < ourEnd)
  {
    if(MemoryInformationClass == MemoryBasicInformation_)
    {
      // Make our memory look like generic committed private memory
      // (not image-backed), so it doesn't stand out
      PMEMORY_BASIC_INFORMATION mbi = (PMEMORY_BASIC_INFORMATION)MemoryInformation;
      mbi->Type = MEM_PRIVATE;    // was MEM_IMAGE — very suspicious
      mbi->AllocationBase = NULL;  // hide allocation base
    }
    else if(MemoryInformationClass == MemoryMappedFilenameInformation_)
    {
      // Return STATUS_ACCESS_DENIED to hide the mapped filename
      // This prevents anti-cheat from getting our DLL path
      return 0xC0000022L;    // STATUS_ACCESS_DENIED
    }
  }

  return status;
}

// ============================================================================
// Install hooks via direct ntdll IAT patching
// ============================================================================
static void InstallNtQueryHooks(HMODULE hOurModule)
{
  // Store our module range
  g_OurModuleBase = (PVOID)hOurModule;

  // Get module size from PE headers (before they're wiped!)
  __try
  {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hOurModule;
    if(pDos->e_magic == IMAGE_DOS_SIGNATURE)
    {
      PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)hOurModule + pDos->e_lfanew);
      if(pNt->Signature == IMAGE_NT_SIGNATURE)
      {
        g_OurModuleSize = pNt->OptionalHeader.SizeOfImage;
      }
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
    // If we can't read headers, use a conservative default (16MB)
    g_OurModuleSize = 16 * 1024 * 1024;
  }

  // Get NtQueryVirtualMemory from ntdll
  HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if(!hNtdll)
    return;

  g_OrigNtQueryVirtualMemory =
      (pfnNtQueryVirtualMemory)GetProcAddress(hNtdll, "NtQueryVirtualMemory");

  if(!g_OrigNtQueryVirtualMemory)
    return;

  // We use inline hook (5-byte jmp) on NtQueryVirtualMemory since
  // ntdll functions are not imported via IAT by most modules.
  // Write a JMP from the original function to our hook.
  DWORD oldProtect;
  if(VirtualProtect(g_OrigNtQueryVirtualMemory, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
  {
#ifdef _WIN64
    // x64: Use a 14-byte absolute jump
    // FF 25 00 00 00 00 [8-byte address]
    BYTE jmpCode[14];
    jmpCode[0] = 0xFF;
    jmpCode[1] = 0x25;
    *(DWORD *)(jmpCode + 2) = 0;    // RIP-relative offset = 0
    *(UINT64 *)(jmpCode + 6) = (UINT64)&Hook_NtQueryVirtualMemory;

    // Save original bytes for calling the real function
    // We need a trampoline: save original instructions, then jump back
    static BYTE s_TrampolineMem[64];
    DWORD trampolineProtect;
    VirtualProtect(s_TrampolineMem, sizeof(s_TrampolineMem), PAGE_EXECUTE_READWRITE, &trampolineProtect);

    // NtQueryVirtualMemory prologue on Win10: 3+5+8=16 bytes of complete instructions.
    // Copying only 14 bytes splits the 8-byte TEST instruction, corrupting the trampoline.
    // We must copy enough bytes to land on a complete instruction boundary.
    // Use a simple length decoder so we never split an instruction.
    static const int kMinCopy = 14;  // minimum bytes to overwrite
    int copyLen = 0;
    const BYTE *src = (const BYTE *)g_OrigNtQueryVirtualMemory;
    // Walk instructions until we have >= kMinCopy bytes covered
    while(copyLen < kMinCopy)
    {
      // Minimal x64 length decoder for the syscall stub patterns we care about.
      // Covers: REX prefixes, 1/2/3-byte opcodes, ModRM/SIB/disp, immediates.
      BYTE b = src[copyLen];
      int len = 1;
      // REX prefix (40-4F)
      bool hasREX = (b >= 0x40 && b <= 0x4F);
      if(hasREX) { copyLen++; b = src[copyLen]; len = 1; }
      if(b >= 0xB8 && b <= 0xBF)  // MOV r, imm32 (or imm64 with REX.W)
      {
        len = hasREX ? 9 : 5;
      }
      else if(b == 0x8B || b == 0x8A || b == 0x89 || b == 0x88)  // MOV r, r/m (or reverse)
      {
        BYTE modrm = src[copyLen + 1];
        int mod = (modrm >> 6) & 3;
        int rm  = modrm & 7;
        len = 2;
        if(mod != 3 && rm == 4) len++;   // SIB
        if(mod == 0 && rm == 5) len += 4;
        else if(mod == 0 && rm == 4 && (src[copyLen+2] & 7) == 5) len += 4;
        else if(mod == 1) len += 1;
        else if(mod == 2) len += 4;
      }
      else if(b == 0xF6 || b == 0xF7)  // TEST/NOT/NEG r/m, imm
      {
        BYTE modrm = src[copyLen + 1];
        int mod = (modrm >> 6) & 3;
        int rm  = modrm & 7;
        int reg = (modrm >> 3) & 7;
        len = 2;
        if(mod != 3 && rm == 4) len++;   // SIB
        if(mod == 0 && rm == 5) len += 4;
        else if(mod == 0 && rm == 4 && (src[copyLen+2] & 7) == 5) len += 4;
        else if(mod == 1) len += 1;
        else if(mod == 2) len += 4;
        if(reg == 0) len += (b == 0xF6 ? 1 : 4);   // imm8/imm32 for TEST
      }
      else if(b == 0x0F)  // 2-byte opcode
      {
        len = 2;  // e.g. SYSCALL (0F 05), SYSRET (0F 07)
      }
      else if(b == 0x75 || b == 0x74 || b == 0xEB)  // JNZ/JZ/JMP short
      {
        len = 2;
      }
      else if(b == 0xC3 || b == 0xCD)  // RET, INT n
      {
        len = (b == 0xCD) ? 2 : 1;
      }
      else
      {
        len = 1;  // fallback
      }
      copyLen += len;
    }

    memcpy(s_TrampolineMem, g_OrigNtQueryVirtualMemory, copyLen);

    // Add jump back to original function + copyLen
    int jmpOff = copyLen;
    s_TrampolineMem[jmpOff + 0] = 0xFF;
    s_TrampolineMem[jmpOff + 1] = 0x25;
    *(DWORD *)(s_TrampolineMem + jmpOff + 2) = 0;
    *(UINT64 *)(s_TrampolineMem + jmpOff + 6) = (UINT64)((BYTE *)g_OrigNtQueryVirtualMemory + copyLen);

    // Update orig pointer to trampoline
    g_OrigNtQueryVirtualMemory = (pfnNtQueryVirtualMemory)(void *)s_TrampolineMem;

    // Write the hook to the REAL function (not the trampoline!)
    memcpy((BYTE *)GetProcAddress(hNtdll, "NtQueryVirtualMemory"), jmpCode, sizeof(jmpCode));
#else
    // x86: 5-byte relative jump
    BYTE jmpCode[5];
    jmpCode[0] = 0xE9;
    *(DWORD *)(jmpCode + 1) = (DWORD)((BYTE *)&Hook_NtQueryVirtualMemory -
                                       (BYTE *)g_OrigNtQueryVirtualMemory - 5);

    static BYTE s_TrampolineMem[32];
    DWORD trampolineProtect;
    VirtualProtect(s_TrampolineMem, sizeof(s_TrampolineMem), PAGE_EXECUTE_READWRITE, &trampolineProtect);

    memcpy(s_TrampolineMem, g_OrigNtQueryVirtualMemory, 5);
    s_TrampolineMem[5] = 0xE9;
    *(DWORD *)(s_TrampolineMem + 6) = (DWORD)((BYTE *)g_OrigNtQueryVirtualMemory + 5 -
                                               (s_TrampolineMem + 10));

    pfnNtQueryVirtualMemory realFunc = g_OrigNtQueryVirtualMemory;
    g_OrigNtQueryVirtualMemory = (pfnNtQueryVirtualMemory)(void *)s_TrampolineMem;
    memcpy(realFunc, jmpCode, sizeof(jmpCode));
#endif

    VirtualProtect(GetProcAddress(hNtdll, "NtQueryVirtualMemory"), 16, oldProtect, &oldProtect);
  }
}
