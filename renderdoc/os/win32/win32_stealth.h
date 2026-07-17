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
typedef NTSTATUS(NTAPI *PFN_LdrLockLoaderLock)(ULONG flags, ULONG *disposition,
                                               ULONG_PTR *cookie);
typedef NTSTATUS(NTAPI *PFN_LdrUnlockLoaderLock)(ULONG flags, ULONG_PTR cookie);

static BOOL UnlinkModuleFromPEB(HMODULE hModule)
{
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  PFN_LdrLockLoaderLock lockLoader =
      ntdll ? (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock") : NULL;
  PFN_LdrUnlockLoaderLock unlockLoader =
      ntdll ? (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock") : NULL;
  if(lockLoader == NULL || unlockLoader == NULL)
    return FALSE;

  ULONG disposition = 0;
  ULONG_PTR cookie = 0;
  if(lockLoader(0, &disposition, &cookie) < 0)
    return FALSE;

  BOOL unlinked = FALSE;
  LIST_ENTRY *unlinkEntries[4] = {};
  LIST_ENTRY unlinkSnapshots[4] = {};
  SIZE_T unlinkCount = 0;
  __try
  {
    // Get PEB via TEB (x64: GS:[0x60], x86: FS:[0x30])
#ifdef _WIN64
    PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
    PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

    if(pPEB && pPEB->Ldr)
    {
      // Cast to our full definition that includes InLoadOrderModuleList
      PPEB_LDR_DATA_FULL pLdr = (PPEB_LDR_DATA_FULL)pPEB->Ldr;

      // Walk InLoadOrderModuleList to find our entry
      PLIST_ENTRY head = &pLdr->InLoadOrderModuleList;
      PLIST_ENTRY current = head->Flink;

      while(current != head)
      {
        PLDR_DATA_TABLE_ENTRY_FULL entry =
            CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
        current = current->Flink;

        if(entry->DllBase == (PVOID)hModule)
        {
          unlinkEntries[0] = &entry->InLoadOrderLinks;
          unlinkEntries[1] = &entry->InMemoryOrderLinks;
          unlinkEntries[2] = &entry->InInitializationOrderLinks;
          unlinkEntries[3] = &entry->HashLinks;

          // Validate and snapshot every link before the first irreversible write. The loader lock
          // keeps the lists stable; snapshots let the exception path roll back a partial commit.
          BOOL validLinks = TRUE;
          for(SIZE_T i = 0; i < ARRAY_COUNT(unlinkEntries); i++)
          {
            LIST_ENTRY *link = unlinkEntries[i];
            if(link->Flink == NULL || link->Blink == NULL || link->Flink->Blink != link ||
               link->Blink->Flink != link)
            {
              validLinks = FALSE;
              break;
            }
            unlinkSnapshots[i] = *link;
          }

          if(!validLinks)
            break;

          for(SIZE_T i = 0; i < ARRAY_COUNT(unlinkEntries); i++)
          {
            // Include the current entry before modifying it so even a mid-write exception restores
            // this list along with every previously removed list.
            unlinkCount = i + 1;
            SafeUnlinkEntry(unlinkEntries[i]);
          }
          unlinked = TRUE;

          // Zero out the DLL name strings to prevent string scanning.
          if(entry->BaseDllName.Buffer)
          {
            DWORD oldProtect = 0;
            if(VirtualProtect(entry->BaseDllName.Buffer, entry->BaseDllName.MaximumLength,
                              PAGE_READWRITE, &oldProtect))
            {
              SecureZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.MaximumLength);
              VirtualProtect(entry->BaseDllName.Buffer, entry->BaseDllName.MaximumLength,
                             oldProtect, &oldProtect);
            }
            entry->BaseDllName.Length = 0;
          }

          if(entry->FullDllName.Buffer)
          {
            DWORD oldProtect = 0;
            if(VirtualProtect(entry->FullDllName.Buffer, entry->FullDllName.MaximumLength,
                              PAGE_READWRITE, &oldProtect))
            {
              SecureZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.MaximumLength);
              VirtualProtect(entry->FullDllName.Buffer, entry->FullDllName.MaximumLength,
                             oldProtect, &oldProtect);
            }
            entry->FullDllName.Length = 0;
          }
          break;
        }
      }
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
    if(!unlinked && unlinkCount > 0)
    {
      __try
      {
        while(unlinkCount > 0)
        {
          SIZE_T i = --unlinkCount;
          LIST_ENTRY *link = unlinkEntries[i];
          const LIST_ENTRY snapshot = unlinkSnapshots[i];
          link->Flink = snapshot.Flink;
          link->Blink = snapshot.Blink;
          snapshot.Flink->Blink = link;
          snapshot.Blink->Flink = link;
        }
      }
      __except(EXCEPTION_EXECUTE_HANDLER)
      {
        // The loader metadata was already corrupt if restoring validated pointers also faults.
      }
    }
  }

  unlockLoader(0, cookie);
  return unlinked;
}

// ============================================================================
// Combined stealth: PE wipe + PEB unlink
// ============================================================================
static BOOL PrepareModuleSignatureWipe(HMODULE hModule, PIMAGE_NT_HEADERS *ntHeaders,
                                       SIZE_T *wipeSize, DWORD *oldProtect)
{
  BOOL prepared = FALSE;

  // Wipe only the identifying signatures in the PE header.
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
        *ntHeaders = pNt;
        *wipeSize = pDos->e_lfanew + sizeof(DWORD);
        prepared = VirtualProtect(hModule, *wipeSize, PAGE_READWRITE, oldProtect);
      }
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER) {}

  return prepared;
}

static BOOL ApplyModuleStealth(HMODULE hModule)
{
  if(hModule == NULL)
    return FALSE;

  // Complete every operation that can fail before unlinking the loader entry. After VirtualProtect
  // succeeds the signature wipe is only writes to validated, writable memory, so HooksFailed can
  // never leave an attached process in a half-hidden state.
  PIMAGE_NT_HEADERS ntHeaders = NULL;
  SIZE_T wipeSize = 0;
  DWORD oldProtect = 0;
  if(!PrepareModuleSignatureWipe(hModule, &ntHeaders, &wipeSize, &oldProtect))
    return FALSE;

  if(!UnlinkModuleFromPEB(hModule))
  {
    DWORD ignored = 0;
    VirtualProtect(hModule, wipeSize, oldProtect, &ignored);
    return FALSE;
  }

  SecureZeroMemory(hModule, wipeSize - sizeof(DWORD));
  ntHeaders->Signature = 0;

  // Stealth is already committed at this point. Restoring the original protection is best-effort;
  // it must not turn a successfully hidden module into a reported failure on attach.
  DWORD ignored = 0;
  VirtualProtect(hModule, wipeSize, oldProtect, &ignored);
  FlushInstructionCache(GetCurrentProcess(), hModule, wipeSize);
  return TRUE;
}

#pragma warning(pop)
