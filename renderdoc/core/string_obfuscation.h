/******************************************************************************
 * String Obfuscation - Memory Anti-Detection
 *
 * This file provides string obfuscation utilities to avoid memory scanning
 * detection by anti-cheat systems. Strings are encrypted at compile time
 * and only decrypted when needed.
 ******************************************************************************/

#pragma once

#include <string>
#include <vector>
#include <ctime>

// ============================================================================
// Compile-time XOR Encryption
// ============================================================================

// Generate a simple key based on compile time
#define OBFUSCATE_KEY ((__TIME__[7] * __TIME__[6] * __TIME__[5] * __TIME__[4] * __TIME__[3] * __TIME__[2] * __TIME__[1] * __TIME__[0]) % 251)

// XOR encryption/decryption
template<int N>
struct ObfuscatedString {
    char data[N];
    unsigned char key;
    
    // Constructor: encrypt string at compile time
    constexpr ObfuscatedString(const char* str) : key(OBFUSCATE_KEY) {
        for (int i = 0; i < N; ++i) {
            data[i] = str[i] ^ key;
        }
    }
    
    // Decrypt and return as std::string
    std::string decrypt() const {
        std::string result;
        result.reserve(N);
        for (int i = 0; i < N; ++i) {
            result += (char)(data[i] ^ key);
        }
        return result;
    }
    
    // Decrypt and return as C string (thread-local storage)
    const char* decrypt_cstr() const {
        static thread_local char buffer[256];
        for (int i = 0; i < N && i < 255; ++i) {
            buffer[i] = (char)(data[i] ^ key);
        }
        buffer[N < 255 ? N : 255] = '\0';
        return buffer;
    }
};

// Macro to create obfuscated string literals
#define OBFUSCATE(str) ObfuscatedString<sizeof(str)>(str).decrypt()
#define OBFUSCATE_CSTR(str) ObfuscatedString<sizeof(str)>(str).decrypt_cstr()

// ============================================================================
// String Building (Split sensitive strings)
// ============================================================================

// Helper to concatenate strings
template<typename... Args>
std::string BUILD_STRING(Args... args) {
    std::string result;
    ((result += args), ...);
    return result;
}

// ============================================================================
// Static Cache Version (for frequently used strings)
// ============================================================================

template<int N>
struct ObfuscatedStringStatic {
    char data[N];
    unsigned char key;
    mutable std::string cached;
    mutable bool decrypted = false;
    
    constexpr ObfuscatedStringStatic(const char* str) : key(OBFUSCATE_KEY) {
        for (int i = 0; i < N; ++i) {
            data[i] = str[i] ^ key;
        }
    }
    
    // Decrypt and cache result
    const std::string& decrypt() const {
        if (!decrypted) {
            cached.reserve(N);
            for (int i = 0; i < N; ++i) {
                cached += (char)(data[i] ^ key);
            }
            decrypted = true;
        }
        return cached;
    }
};

#define OBFUSCATE_STATIC(str) ObfuscatedStringStatic<sizeof(str)>(str).decrypt()

// ============================================================================
// Wide String Support
// ============================================================================

template<int N>
struct ObfuscatedWideString {
    wchar_t data[N];
    unsigned char key;
    
    constexpr ObfuscatedWideString(const wchar_t* str) : key(OBFUSCATE_KEY) {
        for (int i = 0; i < N; ++i) {
            data[i] = str[i] ^ key;
        }
    }
    
    std::wstring decrypt() const {
        std::wstring result;
        result.reserve(N);
        for (int i = 0; i < N; ++i) {
            result += (wchar_t)(data[i] ^ key);
        }
        return result;
    }
    
    const wchar_t* decrypt_cstr() const {
        static thread_local wchar_t buffer[256];
        for (int i = 0; i < N && i < 255; ++i) {
            buffer[i] = (wchar_t)(data[i] ^ key);
        }
        buffer[N < 255 ? N : 255] = L'\0';
        return buffer;
    }
};

#define OBFUSCATE_W(str) ObfuscatedWideString<sizeof(str)/sizeof(wchar_t)>(str).decrypt()
#define OBFUSCATE_WCSTR(str) ObfuscatedWideString<sizeof(str)/sizeof(wchar_t)>(str).decrypt_cstr()

// ============================================================================
// Common Obfuscated Strings
// ============================================================================

// Pre-obfuscated common strings to avoid repetition
#define OBF_RENDERDOC OBF_SYSTEM_LOAD
#define OBF_RENDERDOC_CSTR OBF_SYSTEM_LOAD_CSTR
#define OBF_RENDERDOC_W OBF_SYSTEM_LOAD_W
#define OBF_RENDERDOC_WCSTR OBF_SYSTEM_LOAD_WCSTR

// Alternative names
#define OBF_SYSTEM_LOAD OBFUSCATE("SystemLoad")
#define OBF_SYSTEM_LOAD_CSTR OBFUSCATE_CSTR("SystemLoad")
#define OBF_SYSTEM_LOAD_W OBFUSCATE_W(L"SystemLoad")
#define OBF_SYSTEM_LOAD_WCSTR OBFUSCATE_WCSTR(L"SystemLoad")

// File extensions and paths
#define OBF_CONF_EXT OBFUSCATE(".conf")
#define OBF_DLL_EXT OBFUSCATE(".dll")
#define OBF_RENDERDOC_CONF OBF_SYSTEM_LOAD_CONF
#define OBF_SYSTEM_LOAD_CONF OBFUSCATE("system_load.conf")

// Registry keys
#define OBF_REG_SOFTWARE_RENDERDOC OBF_REG_SOFTWARE_SYSTEM_LOAD
#define OBF_REG_SOFTWARE_SYSTEM_LOAD OBFUSCATE("Software\\Microsoft\\SystemLoad")

// Window class names
#define OBF_WINCLASS_RENDERDOC OBF_WINCLASS_SYSTEM_LOAD
#define OBF_WINCLASS_SYSTEM_LOAD OBFUSCATE_WCSTR(L"SystemLoadClass")

// Environment variables
#define OBF_ENV_VULKAN_RENDERDOC OBF_ENV_VULKAN_SYSTEM_LOAD
#define OBF_ENV_VULKAN_SYSTEM_LOAD OBFUSCATE("ENABLE_VULKAN_SQC_LAYER_ACTIVATE_")

// ============================================================================
// Instance Access Obfuscation
// ============================================================================

// Hide SanQiInternalLib::Inst() calls to avoid memory scanning
// Use the SanQiInternalLib namespace directly since we're not remapping it
#define SystemInst() SanQiInternalLib::Inst()
#define GetSystemInstance() SanQiInternalLib::Inst()
#define CoreInstance() SanQiInternalLib::Inst()
