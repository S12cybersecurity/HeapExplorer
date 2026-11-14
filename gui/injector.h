#pragma once
#include <Windows.h>
#include <string>

namespace Injector {
    struct Result {
        bool success = false;
        DWORD pid = 0;
        std::string error;
    };

    std::string GetWorkerDllPath();
    Result LaunchAndInject(const std::string& exePath, const std::string& args = "");
    Result AttachToProcess(DWORD pid);
}
