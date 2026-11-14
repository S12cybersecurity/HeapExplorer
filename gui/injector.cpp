#include "injector.h"

static bool InjectDLL(HANDLE hProcess, const char* dllPath) {
    SIZE_T pathLen = strlen(dllPath) + 1;

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathLen,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathLen, NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLib  = GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)pLoadLib,
                                         remoteMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return true;
}

std::string Injector::GetWorkerDllPath() {
    char buf[MAX_PATH];
    GetModuleFileNameA(NULL, buf, MAX_PATH);
    std::string dir(buf);
    dir = dir.substr(0, dir.find_last_of('\\') + 1);
    return dir + "worker.dll";
}

Injector::Result Injector::LaunchAndInject(const std::string& exePath,
                                            const std::string& args) {
    Result r;
    std::string dll = GetWorkerDllPath();

    if (GetFileAttributesA(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        r.error = "worker.dll not found next to HeapExplorer.exe";
        return r;
    }

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    std::string cmdline = "\"" + exePath + "\"";
    if (!args.empty()) cmdline += " " + args;

    if (!CreateProcessA(NULL, (LPSTR)cmdline.c_str(), NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        r.error = "CreateProcess failed (" + std::to_string(GetLastError()) + ")";
        return r;
    }

    if (!InjectDLL(pi.hProcess, dll.c_str())) {
        r.error = "Injection failed (" + std::to_string(GetLastError()) + ")";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return r;
    }

    ResumeThread(pi.hThread);
    r.success = true;
    r.pid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return r;
}

Injector::Result Injector::AttachToProcess(DWORD pid) {
    Result r;
    std::string dll = GetWorkerDllPath();

    if (GetFileAttributesA(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        r.error = "worker.dll not found next to HeapExplorer.exe";
        return r;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        r.error = "OpenProcess failed (" + std::to_string(GetLastError()) + ")";
        return r;
    }

    if (!InjectDLL(hProcess, dll.c_str())) {
        r.error = "Injection failed (" + std::to_string(GetLastError()) + ")";
        CloseHandle(hProcess);
        return r;
    }

    r.success = true;
    r.pid = pid;
    CloseHandle(hProcess);
    return r;
}
