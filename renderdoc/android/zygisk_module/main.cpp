/******************************************************************************
 * Zygisk Module — SystemLoad Capture Injection
 *
 * This module uses the Zygisk framework (Magisk) to inject our capture
 * library into target game processes at the earliest possible point —
 * right after Zygote forks the process, before any anti-cheat code runs.
 *
 * Build as a Magisk module with Zygisk support.
 * Place the compiled .so as:
 *   /data/adb/modules/systemload_zygisk/zygisk/armeabi-v7a.so
 *   /data/adb/modules/systemload_zygisk/zygisk/arm64-v8a.so
 *
 * Configuration:
 *   /data/adb/modules/systemload_zygisk/target_packages.txt
 *   — One package name per line (e.g., com.example.game)
 ******************************************************************************/

// Zygisk API header — provided by the Magisk SDK
// See https://github.com/topjohnwu/Magisk/blob/master/native/src/include/zygisk/api.hpp

#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <android/log.h>
#include <sys/mman.h>
#include <jni.h>

// Minimal Zygisk API interface (from Magisk SDK)
// In production, use the actual zygisk/api.hpp from Magisk SDK
namespace zygisk {

enum Option { DLCLOSE_MODULE_LIBRARY = 0, FORCE_DENYLIST_UNMOUNT = 1 };
enum StateFlag { PROCESS_GRANTED_ROOT = 0, PROCESS_ON_DENYLIST = 1 };

struct Api;
struct AppSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jint &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jstring &instruction_set;
    jstring &app_data_dir;
    // ... more fields
};
struct ServerSpecializeArgs {};

class ModuleBase {
public:
    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
};

struct Api {
    void setOption(Option opt);
    bool getStateBool(StateFlag flag);
    int getModuleDir();
    int connectCompanion();
    void pltHookRegister(const char *regex, const char *symbol, void *newFunc, void **oldFunc);
    void pltHookExclude(const char *regex, const char *symbol);
    bool pltHookCommit();
};

} // namespace zygisk

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "SLZygisk", __VA_ARGS__)

// ============================================================================
// Target package list management
// ============================================================================

static bool IsTargetPackage(const char *packageName, int moduleDir)
{
    if(!packageName) return false;

    char configPath[512];
    snprintf(configPath, sizeof(configPath), "/proc/self/fd/%d/target_packages.txt", moduleDir);

    FILE *f = fopen(configPath, "r");
    if(!f) return false;

    char line[256];
    bool found = false;
    while(fgets(line, sizeof(line), f))
    {
        // Strip trailing newline
        size_t len = strlen(line);
        while(len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        if(len > 0 && strcmp(line, packageName) == 0)
        {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

// ============================================================================
// Capture library loader
// ============================================================================

static void LoadCaptureLibrary(int moduleDir)
{
    char libPath[512];

#if defined(__aarch64__)
    snprintf(libPath, sizeof(libPath), "/proc/self/fd/%d/lib/arm64-v8a/libVkLayer_GLES_SystemLoad.so", moduleDir);
#elif defined(__arm__)
    snprintf(libPath, sizeof(libPath), "/proc/self/fd/%d/lib/armeabi-v7a/libVkLayer_GLES_SystemLoad.so", moduleDir);
#else
    return; // Unsupported architecture
#endif

    void *handle = dlopen(libPath, RTLD_NOW);
    if(handle)
    {
        LOGD("Capture library loaded: %s", libPath);
    }
    else
    {
        LOGD("Failed to load capture library: %s (%s)", libPath, dlerror());
    }
}

// ============================================================================
// Zygisk Module Implementation
// ============================================================================

class SystemLoadModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        int moduleDir = api->getModuleDir();

        // Get package name from nice_name
        const char *packageName = nullptr;
        if(args->nice_name) {
            packageName = env->GetStringUTFChars(args->nice_name, nullptr);
        }

        if(packageName && IsTargetPackage(packageName, moduleDir)) {
            LOGD("Target package detected: %s — will inject capture library", packageName);
            shouldInject = true;
            savedModuleDir = moduleDir;
        } else {
            // Not our target — unload this module to save memory
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }

        if(packageName && args->nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, packageName);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if(shouldInject) {
            LOGD("postAppSpecialize: Injecting capture library...");
            LoadCaptureLibrary(savedModuleDir);
        }
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool shouldInject = false;
    int savedModuleDir = -1;
};

// Register module with Zygisk
// REGISTER_ZYGISK_MODULE(SystemLoadModule)
// ^ Uncomment when building with real Magisk SDK
