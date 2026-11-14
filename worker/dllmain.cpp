#include <Windows.h>
#include "pipe_client.h"
#include "hooks.h"
#include "snapshot.h"
#include "common/protocol.h"

static PipeClient g_pipe;
static HANDLE     g_thread = NULL;
static volatile bool g_running = false;

static DWORD WINAPI WorkerThread(LPVOID) {
    if (!g_pipe.Connect()) return 1;

    HANDLE heaps[256];
    DWORD heap_count = GetProcessHeaps(256, heaps);
    WorkerReadyMsg ready = {};
    ready.pid        = GetCurrentProcessId();
    ready.heap_count = heap_count;
    g_pipe.Send(MSG_WORKER_READY, &ready, sizeof(ready));

    Snapshot::Take(g_pipe);
    Hooks::Install(&g_pipe);

    uint8_t cmd_buf[256];
    MessageHeader hdr;
    while (g_running) {
        g_pipe.FlushEvents();

        if (g_pipe.HasData()) {
            if (!g_pipe.Receive(hdr, cmd_buf, sizeof(cmd_buf)))
                break;

            switch (hdr.type) {
            case MSG_SNAPSHOT_REQUEST:
                Snapshot::Take(g_pipe);
                break;
            case MSG_HOOKS_ENABLE:
                if (!Hooks::IsInstalled()) Hooks::Install(&g_pipe);
                break;
            case MSG_HOOKS_DISABLE:
                Hooks::Remove();
                break;
            }
        } else {
            Sleep(1);
        }
    }

    Hooks::Remove();
    g_pipe.Disconnect();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        g_pipe.Init();
        g_running = true;
        g_thread = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        g_running = false;
        if (g_thread) {
            WaitForSingleObject(g_thread, 3000);
            CloseHandle(g_thread);
        }
        g_pipe.Cleanup();
        break;
    }
    return TRUE;
}
