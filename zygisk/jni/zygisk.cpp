#include "zygisk.hpp"
#include "dobby.h"
#include <unistd.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <sys/socket.h>
#include <vector>
#include <fstream>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "SNFix/Zygisk", __VA_ARGS__)

static void companion(int fd) {
    std::ifstream ifs("/data/adb/SNFix.dex", std::ios::binary | std::ios::ate);
    int size = ifs.tellg();
    ifs.seekg(std::ios::beg);

    send(fd, &size, sizeof(size), 0);

    std::vector<char> dexFile(size);
    ifs.read(dexFile.data(), size);

    send(fd, dexFile.data(), size, 0);

    ifs.close();
    dexFile.clear();
    dexFile.shrink_to_fit();
}

typedef void (*T_Callback)(void *, const char *, const char *, uint32_t);

static void (*o_hook)(const prop_info *, T_Callback, void *);

static T_Callback o_callback;

static void
handle_system_property(void *cookie, const char *name, const char *value, uint32_t serial) {
    if (std::string_view(name).compare("ro.product.first_api_level") == 0) {
        LOGI("Set first_api_level to 32, original value: %s", value);
        value = "32";
    }
    o_callback(cookie, name, value, serial);
}

static void my_hook(const prop_info *pi, T_Callback callback, void *cookie) {
    o_callback = callback;
    o_hook(pi, handle_system_property, cookie);
}

static bool isFirstApiLevelGreater32() {
    char value[PROP_VALUE_MAX];
    if (__system_property_get("ro.product.first_api_level", value) < 1) return false;
    int first_api_level = std::atoi(value);
    return first_api_level > 32;
}

using namespace zygisk;

class PlayIntegrityFix : public ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        this->hookProps = false;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        auto rawProcess = env->GetStringUTFChars(args->nice_name, nullptr);
        std::string process(rawProcess);
        env->ReleaseStringUTFChars(args->nice_name, rawProcess);

        if (!process.starts_with("com.google.android.gms")) {
            api->setOption(DLCLOSE_MODULE_LIBRARY);
            return;
        }

        api->setOption(FORCE_DENYLIST_UNMOUNT);

        if (process.ends_with("unstable")) {
            hookProps = isFirstApiLevelGreater32();
            if (!hookProps) {
                api->setOption(DLCLOSE_MODULE_LIBRARY);
            }
            int fd = api->connectCompanion();
            int size;
            recv(fd, &size, sizeof(size), 0);
            dexFile.resize(size);
            recv(fd, dexFile.data(), size, 0);
            close(fd);
        } else {
            api->setOption(DLCLOSE_MODULE_LIBRARY);
        }

        process.clear();
        process.shrink_to_fit();
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (dexFile.empty()) return;

        LOGI("Dex file size: %d", (int) dexFile.size());

        if (hookProps) {
            void *handle = DobbySymbolResolver(nullptr, "__system_property_read_callback");
            if (handle == nullptr) {
                LOGI("Error, can't get handle");
                dexFile.clear();
                dexFile.shrink_to_fit();
                return;
            }
            LOGI("Got handle at %p", handle);
            DobbyHook(handle, (dobby_dummy_func_t) my_hook, (dobby_dummy_func_t *) &o_hook);
        }

        LOGI("get system classloader");
        auto clClass = env->FindClass("java/lang/ClassLoader");
        auto getSystemClassLoader = env->GetStaticMethodID(clClass, "getSystemClassLoader",
                                                           "()Ljava/lang/ClassLoader;");
        auto systemClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);

        LOGI("create InMemoryDexClassLoader");
        auto dexClClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
        auto dexClInit = env->GetMethodID(dexClClass, "<init>",
                                          "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        auto buffer = env->NewDirectByteBuffer(dexFile.data(), dexFile.size());
        auto dexCl = env->NewObject(dexClClass, dexClInit, buffer, systemClassLoader);

        LOGI("load class");
        auto loadClass = env->GetMethodID(clClass, "loadClass",
                                          "(Ljava/lang/String;)Ljava/lang/Class;");
        auto entryClassName = env->NewStringUTF("dev.kdrag0n.safetynetfix.EntryPoint");
        auto entryClassObj = env->CallObjectMethod(dexCl, loadClass, entryClassName);

        LOGI("call init");
        auto entryClass = (jclass) entryClassObj;
        auto entryInit = env->GetStaticMethodID(entryClass, "init", "()V");
        env->CallStaticVoidMethod(entryClass, entryInit);

        LOGI("cleaning");
        dexFile.clear();
        dexFile.shrink_to_fit();
        env->DeleteLocalRef(clClass);
        env->DeleteLocalRef(systemClassLoader);
        env->DeleteLocalRef(dexClClass);
        env->DeleteLocalRef(buffer);
        env->DeleteLocalRef(dexCl);
        env->DeleteLocalRef(entryClassName);
        env->DeleteLocalRef(entryClassObj);
        env->DeleteLocalRef(entryClass);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api;
    JNIEnv *env;
    std::vector<char> dexFile;
    bool hookProps;
};

REGISTER_ZYGISK_MODULE(PlayIntegrityFix)

REGISTER_ZYGISK_COMPANION(companion)