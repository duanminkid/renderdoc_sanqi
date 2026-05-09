/******************************************************************************
 * Vulkan Layer Hiding - vkEnumerateInstanceLayerProperties Filter
 *
 * Hooks vulkan-1.dll!vkEnumerateInstanceLayerProperties to remove our
 * capture layer from the enumeration results. Anti-cheat systems commonly
 * call this API to detect debugging/capture layers.
 *
 * Uses MinHook for inline hooking since vulkan-1.dll may be loaded after us.
 * Call InstallVkLayerHide() AFTER vulkan-1.dll is loaded.
 ******************************************************************************/

#pragma once

#include <windows.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// Minimal Vulkan type definitions -- avoid dependency on vulkan/vulkan.h
// ============================================================================

#ifndef VK_SUCCESS
#define VK_SUCCESS 0
#define VK_INCOMPLETE 5
#define VK_ERROR_INITIALIZATION_FAILED (-3)
#endif

#ifndef VK_MAX_EXTENSION_NAME_SIZE
#define VK_MAX_EXTENSION_NAME_SIZE 256
#define VK_MAX_DESCRIPTION_SIZE 256
#endif

#ifndef VKAPI_ATTR
#define VKAPI_ATTR
#define VKAPI_CALL __stdcall
#define VKAPI_PTR __stdcall
#endif

typedef int VkResult;

typedef struct VkLayerProperties_Stealth_ {
  char layerName[VK_MAX_EXTENSION_NAME_SIZE];
  uint32_t specVersion;
  uint32_t implementationVersion;
  char description[VK_MAX_DESCRIPTION_SIZE];
} VkLayerProperties_Stealth;

// ============================================================================
// Runtime string decoder - XOR obfuscation so strings never appear as
// plaintext in .text or .rdata sections. Key = 0x5A.
// To generate: for each char c, store (c ^ 0x5A) as the byte value.
// ============================================================================

#define SQC_XK 0x5A

static inline void SqcDecodeStr(char *dst, const unsigned char *enc, int len)
{
  for(int i = 0; i < len; i++)
    dst[i] = (char)(enc[i] ^ SQC_XK);
  dst[len] = '\0';
}

// Suffix-based matching: check if s ends with suffix
static inline bool EndsWith(const char *s, const char *suffix)
{
  size_t sl = strlen(s), el = strlen(suffix);
  return sl >= el && memcmp(s + sl - el, suffix, el) == 0;
}

// Check if a layer name should be hidden
static inline bool ShouldHideLayer(const char *layerName)
{
  if(!layerName)
    return false;

  char tmp[256];

  // "VK_LAYER_MICROSOFT_SystemLoad" (29 chars) XOR 0x5A
  // V=0x0C K=0x11 _=0x05 L=0x16 A=0x1B Y=0x03 E=0x1F R=0x08 _=0x05
  // M=0x17 I=0x13 C=0x19 R=0x08 O=0x15 S=0x09 O=0x15 F=0x1C T=0x0E _=0x05
  // S=0x09 y=0x23 s=0x29 t=0x2E e=0x3F m=0x37 L=0x16 o=0x35 a=0x3B d=0x3E
  static const unsigned char kEnc1[] = {
    0x0C,0x11,0x05,0x16,0x1B,0x03,0x1F,0x08,0x05,
    0x17,0x13,0x19,0x08,0x15,0x09,0x15,0x1C,0x0E,0x05,
    0x09,0x23,0x29,0x2E,0x3F,0x37,0x16,0x35,0x3B,0x3E
  };
  SqcDecodeStr(tmp, kEnc1, 29);
  if(strcmp(layerName, tmp) == 0) return true;

  // "VK_LAYER_KID_Capture" (20 chars) XOR 0x5A
  // V=0x0C K=0x11 _=0x05 L=0x16 A=0x1B Y=0x03 E=0x1F R=0x08 _=0x05
  // K=0x11 I=0x13 D=0x1E _=0x05
  // C=0x19 a=0x3B p=0x2A t=0x2E u=0x2F r=0x28 e=0x3F
  static const unsigned char kEnc2[] = {
    0x0C,0x11,0x05,0x16,0x1B,0x03,0x1F,0x08,0x05,
    0x11,0x13,0x1E,0x05,
    0x19,0x3B,0x2A,0x2E,0x2F,0x28,0x3F
  };
  SqcDecodeStr(tmp, kEnc2, 20);
  if(strcmp(layerName, tmp) == 0) return true;

  // "VK_LAYER_SANQIINJECTTOOL_Capture" (32 chars) XOR 0x5A
  // V=0x0C K=0x11 _=0x05 L=0x16 A=0x1B Y=0x03 E=0x1F R=0x08 _=0x05
  // S=0x09 A=0x1B N=0x14 Q=0x0B I=0x13 I=0x13 N=0x14 J=0x10 E=0x1F C=0x19 T=0x0E T=0x0E O=0x15 O=0x15 L=0x16 _=0x05
  // C=0x19 a=0x3B p=0x2A t=0x2E u=0x2F r=0x28 e=0x3F
  static const unsigned char kEnc3[] = {
    0x0C,0x11,0x05,0x16,0x1B,0x03,0x1F,0x08,0x05,
    0x09,0x1B,0x14,0x0B,0x13,0x13,0x14,0x10,0x1F,0x19,0x0E,0x0E,0x15,0x15,0x16,0x05,
    0x19,0x3B,0x2A,0x2E,0x2F,0x28,0x3F
  };
  SqcDecodeStr(tmp, kEnc3, 32);
  if(strcmp(layerName, tmp) == 0) return true;

  // Hide any layer ending with "Capture" (7 chars) XOR 0x5A
  // C=0x19 a=0x3B p=0x2A t=0x2E u=0x2F r=0x28 e=0x3F
  static const unsigned char kCapSuf[] = {0x19,0x3B,0x2A,0x2E,0x2F,0x28,0x3F};
  SqcDecodeStr(tmp, kCapSuf, 7);
  if(EndsWith(layerName, tmp)) return true;

  // Hide any layer ending with "SystemLoad" (10 chars) XOR 0x5A
  // S=0x09 y=0x23 s=0x29 t=0x2E e=0x3F m=0x37 L=0x16 o=0x35 a=0x3B d=0x3E
  static const unsigned char kSysLdSuf[] = {0x09,0x23,0x29,0x2E,0x3F,0x37,0x16,0x35,0x3B,0x3E};
  SqcDecodeStr(tmp, kSysLdSuf, 10);
  if(EndsWith(layerName, tmp)) return true;

  return false;
}

// ============================================================================
// Hooked vkEnumerateInstanceLayerProperties
// ============================================================================

typedef VkResult(VKAPI_PTR *PFN_vkEnumerateInstanceLayerProperties_t)(
    uint32_t *pPropertyCount, VkLayerProperties_Stealth *pProperties);

static PFN_vkEnumerateInstanceLayerProperties_t g_RealEnumInstanceLayers = NULL;

static VKAPI_ATTR VkResult VKAPI_CALL Hook_vkEnumerateInstanceLayerProperties(
    uint32_t *pPropertyCount, VkLayerProperties_Stealth *pProperties)
{
  if(!g_RealEnumInstanceLayers)
    return VK_ERROR_INITIALIZATION_FAILED;

  VkResult result = g_RealEnumInstanceLayers(pPropertyCount, pProperties);

  if(result != VK_SUCCESS || !pPropertyCount)
    return result;

  if(pProperties == NULL)
  {
    // Query phase: call real function, then subtract hidden layer count.
    uint32_t realCount = *pPropertyCount;
    VkLayerProperties_Stealth *tmpProps = new VkLayerProperties_Stealth[realCount];
    VkResult r2 = g_RealEnumInstanceLayers(&realCount, tmpProps);

    uint32_t hiddenCount = 0;
    if(r2 == VK_SUCCESS)
    {
      for(uint32_t i = 0; i < realCount; i++)
      {
        if(ShouldHideLayer(tmpProps[i].layerName))
          hiddenCount++;
      }
    }
    delete[] tmpProps;

    if(*pPropertyCount >= hiddenCount)
      *pPropertyCount -= hiddenCount;
    return VK_SUCCESS;
  }
  else
  {
    // Fill phase: filter out hidden layers from the result
    uint32_t totalCount = *pPropertyCount;
    uint32_t writeIdx = 0;

    for(uint32_t readIdx = 0; readIdx < totalCount; readIdx++)
    {
      if(!ShouldHideLayer(pProperties[readIdx].layerName))
      {
        if(writeIdx != readIdx)
          pProperties[writeIdx] = pProperties[readIdx];
        writeIdx++;
      }
    }

    *pPropertyCount = writeIdx;
    return VK_SUCCESS;
  }
}

// ============================================================================
// Install the hook on vulkan-1.dll
// ============================================================================
static void InstallVkLayerHide()
{
  HMODULE hVulkan = GetModuleHandleA("vulkan-1.dll");
  if(!hVulkan)
    return;    // Vulkan not loaded yet -- will be hooked when loaded via IAT hooks

  PFN_vkEnumerateInstanceLayerProperties_t realFunc =
      (PFN_vkEnumerateInstanceLayerProperties_t)GetProcAddress(
          hVulkan, "vkEnumerateInstanceLayerProperties");

  if(!realFunc || realFunc == (PFN_vkEnumerateInstanceLayerProperties_t)&Hook_vkEnumerateInstanceLayerProperties)
    return;    // Already hooked or not found

  // Use inline hook (same technique as NtQuery hook)
  DWORD oldProtect;
  if(!VirtualProtect(realFunc, 32, PAGE_EXECUTE_READWRITE, &oldProtect))
    return;

#ifdef _WIN64
  // x64: 14-byte absolute jump
  static BYTE s_VkTrampolineMem[64];
  DWORD trampolineProtect;
  VirtualProtect(s_VkTrampolineMem, sizeof(s_VkTrampolineMem), PAGE_EXECUTE_READWRITE,
                 &trampolineProtect);

  // Save original bytes to trampoline
  memcpy(s_VkTrampolineMem, realFunc, 14);

  // Add jump back to original + 14
  s_VkTrampolineMem[14] = 0xFF;
  s_VkTrampolineMem[15] = 0x25;
  *(DWORD *)(s_VkTrampolineMem + 16) = 0;
  *(UINT64 *)(s_VkTrampolineMem + 20) = (UINT64)((BYTE *)realFunc + 14);

  g_RealEnumInstanceLayers =
      (PFN_vkEnumerateInstanceLayerProperties_t)(void *)s_VkTrampolineMem;

  // Write hook jump
  BYTE jmpCode[14];
  jmpCode[0] = 0xFF;
  jmpCode[1] = 0x25;
  *(DWORD *)(jmpCode + 2) = 0;
  *(UINT64 *)(jmpCode + 6) = (UINT64)&Hook_vkEnumerateInstanceLayerProperties;

  memcpy(realFunc, jmpCode, sizeof(jmpCode));
#else
  // x86: 5-byte relative jump
  static BYTE s_VkTrampolineMem[32];
  DWORD trampolineProtect;
  VirtualProtect(s_VkTrampolineMem, sizeof(s_VkTrampolineMem), PAGE_EXECUTE_READWRITE,
                 &trampolineProtect);

  memcpy(s_VkTrampolineMem, realFunc, 5);
  s_VkTrampolineMem[5] = 0xE9;
  *(DWORD *)(s_VkTrampolineMem + 6) =
      (DWORD)((BYTE *)realFunc + 5 - (s_VkTrampolineMem + 10));

  g_RealEnumInstanceLayers =
      (PFN_vkEnumerateInstanceLayerProperties_t)(void *)s_VkTrampolineMem;

  BYTE jmpCode[5];
  jmpCode[0] = 0xE9;
  *(DWORD *)(jmpCode + 1) = (DWORD)((BYTE *)&Hook_vkEnumerateInstanceLayerProperties -
                                     (BYTE *)realFunc - 5);

  memcpy(realFunc, jmpCode, sizeof(jmpCode));
#endif

  VirtualProtect(realFunc, 32, oldProtect, &oldProtect);
}
