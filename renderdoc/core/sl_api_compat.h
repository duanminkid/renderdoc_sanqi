/******************************************************************************
 * SL API Compatibility Layer
 *
 * This header provides linker-level symbol redirection for tool projects
 * that reference RENDERDOC_* functions to use SL_* (SystemLoad) exports.
 *
 * Usage: Include this header in tool projects (renderdoccmd, qrenderdoc, etc.)
 *        to enable linking against system_load.dll which only exports SL_* symbols.
 *
 * Technical Detail: Uses MSVC's /alternatename linker directive to redirect
 *                   __imp_RENDERDOC_* symbols to __imp_SL_* at link time.
 *****************************************************************************/

#pragma once

#ifdef _WIN32

// Linker symbol redirection: RENDERDOC_* -> SL_*
// Format: /alternatename:search=target
// This tells the linker to resolve references to "search" as "target"

// Memory Management
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_AllocArrayMem=__imp_SL_AllocArrayMem")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_FreeArrayMem=__imp_SL_FreeArrayMem")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_RegisterMemoryRegion=__imp_SL_RegisterMemoryRegion")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_UnregisterMemoryRegion=__imp_SL_UnregisterMemoryRegion")

// Server/Remote Control
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_BecomeRemoteServer=__imp_SL_BecomeRemoteServer")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_CheckRemoteServerConnection=__imp_SL_CheckRemoteServerConnection")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_CreateRemoteServerConnection=__imp_SL_CreateRemoteServerConnection")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_CreateTargetControl=__imp_SL_CreateTargetControl")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_EnumerateRemoteTargets=__imp_SL_EnumerateRemoteTargets")

// Profiling
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_BeginProfileRegion=__imp_SL_BeginProfileRegion")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_EndProfileRegion=__imp_SL_EndProfileRegion")

// Hooking/Injection
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_CanGlobalHook=__imp_SL_CanGlobalHook")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_CanSelfHostedCapture=__imp_SL_CanSelfHostCapture")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_ExecuteAndInject=__imp_SL_ExecuteAndInject")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_InjectIntoProcess=__imp_SL_InjectIntoProcess")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_IsGlobalHookActive=__imp_SL_IsGlobalHookActive")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_StartGlobalHook=__imp_SL_StartGlobalHook")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_StopGlobalHook=__imp_SL_StopGlobalHook")

// Self-Host Capture
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_EndSelfHostCapture=__imp_SL_EndSelfHostCapture")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_StartSelfHostCapture=__imp_SL_StartSelfHostCapture")

// Bug Reports & Diagnostics
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_CreateBugReport=__imp_SL_CreateBugReport")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetCurrentProcessMemoryUsage=__imp_SL_GetCurrentProcessMemoryUsage")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_RunFunctionalTests=__imp_SL_RunFunctionalTests")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_RunUnitTests=__imp_SL_RunUnitTests")

// Capture Options & Configuration
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetDefaultCaptureOptions=__imp_SL_GetDefaultCaptureOptions")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetConfigSetting=__imp_SL_GetConfigSetting")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_SaveConfigSettings=__imp_SL_SaveConfigSettings")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_SetConfigSetting=__imp_SL_SetConfigSetting")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_SetDebugLogFile=__imp_SL_SetDebugLogFile")

// Driver Information
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetDriverInformation=__imp_SL_GetDriverInformation")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetDeviceProtocolController=__imp_SL_GetDeviceProtocolController")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetSupportedDeviceProtocols=__imp_SL_GetSupportedDeviceProtocols")

// Version & Build Info
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetCommitHash=__imp_SL_GetCommitHash")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetVersionString=__imp_SL_GetVersionString")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_IsReleaseBuild=__imp_SL_IsReleaseBuild")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_UpdateInstalledVersionNumber=__imp_SL_UpdateInstalledVersionNumber")

// Replay System
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_InitialiseReplay=__imp_SL_InitialiseReplay")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_ShutdownReplay=__imp_SL_ShutdownReplay")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_OpenCaptureFile=__imp_SL_OpenCaptureFile")

// Capture File Operations
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetLogFile=__imp_SL_GetLogFile")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetLogFileContents=__imp_SL_GetLogFileContents")

// Logging
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_LogMessage=__imp_SL_LogMessage")

// Utility Functions
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_FloatToHalf=__imp_SL_FloatToHalf")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_HalfToFloat=__imp_SL_HalfToFloat")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_InitCamera=__imp_SL_InitCamera")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_NumVerticesPerPrimitive=__imp_SL_NumVerticesPerPrimitive")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_ResourceFormatName=__imp_SL_ResourceFormatName")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_SetColors=__imp_SL_SetColors")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_VertexOffset=__imp_SL_VertexOffset")

// Vulkan Layer Registration
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_CheckAndroidPackage=__imp_SL_CheckAndroidPackage")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_NeedVulkanLayerRegistration=__imp_SL_NeedVulkanLayerRegistration")
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_UpdateVulkanLayerRegistration=__imp_SL_UpdateVulkanLayerRegistration")

// GetAPI - Special case: Direct mapping
#pragma comment(linker, "/alternatename:__imp_RENDERDOC_GetAPI=__imp_SL_GetAPI")

#endif // _WIN32
