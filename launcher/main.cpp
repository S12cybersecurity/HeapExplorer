#include <Windows.h>
#include <cstdio>
#include <string>

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

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("HeapExplorer Launcher\n");
        printf("Usage:\n");
        printf("  launcher.exe <target.exe> [args...]   Launch and inject\n");
        printf("  launcher.exe --pid <PID>              Attach to running process\n");
        return 1;
    }

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string dir(exePath);
    dir = dir.substr(0, dir.find_last_of('\\') + 1);
    std::string dllPath = dir + "worker.dll";

    DWORD attr = GetFileAttributesA(dllPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        printf("[!] worker.dll not found at: %s\n", dllPath.c_str());
        return 1;
    }

    if (argc >= 3 && strcmp(argv[1], "--pid") == 0) {
        DWORD pid = atoi(argv[2]);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            printf("[!] Failed to open PID %u (error %u)\n", pid, GetLastError());
            return 1;
        }
        printf("[*] Attaching to PID %u\n", pid);
        if (!InjectDLL(hProcess, dllPath.c_str())) {
            printf("[!] Injection failed (error %u)\n", GetLastError());
            CloseHandle(hProcess);
            return 1;
        }
        printf("[+] worker.dll injected into PID %u\n", pid);
        CloseHandle(hProcess);
        return 0;
    }

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    std::string cmdline;
    for (int i = 1; i < argc; i++) {
        if (i > 1) cmdline += ' ';
        cmdline += argv[i];
    }

    printf("[*] Launching: %s\n", cmdline.c_str());

    if (!CreateProcessA(NULL, (LPSTR)cmdline.c_str(), NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] CreateProcess failed (error %u)\n", GetLastError());
        return 1;
    }

    printf("[*] PID %u created (suspended), injecting worker...\n", pi.dwProcessId);

    if (!InjectDLL(pi.hProcess, dllPath.c_str())) {
        printf("[!] Injection failed (error %u)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    printf("[+] worker.dll injected, resuming process\n");
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
