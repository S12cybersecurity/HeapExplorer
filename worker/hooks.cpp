#include "hooks.h"
#include "pipe_client.h"
#include "common/protocol.h"
#include <Windows.h>
#include <MinHook.h>

static PipeClient* g_pipe = nullptr;
static bool g_installed = false;

using PFN_RtlAllocateHeap = PVOID(NTAPI*)(PVOID, ULONG, SIZE_T);
using PFN_RtlFreeHeap     = BOOLEAN(NTAPI*)(PVOID, ULONG, PVOID);
using PFN_RtlReAllocateHeap = PVOID(NTAPI*)(PVOID, ULONG, PVOID, SIZE_T);

static PFN_RtlAllocateHeap   OrigAlloc   = nullptr;
static PFN_RtlFreeHeap       OrigFree    = nullptr;
static PFN_RtlReAllocateHeap OrigReAlloc = nullptr;

extern volatile bool g_in_snapshot;
static DWORD g_tls_in_hook = TLS_OUT_OF_INDEXES;

static bool GetInHook() {
    if (g_tls_in_hook == TLS_OUT_OF_INDEXES) return true;
    return TlsGetValue(g_tls_in_hook) != NULL;
}
static void SetInHook(bool val) {
    if (g_tls_in_hook != TLS_OUT_OF_INDEXES)
        TlsSetValue(g_tls_in_hook, val ? (LPVOID)1 : NULL);
}

static void CaptureCallstack(uint8_t& out_count, uint64_t* out_frames,
                              uint8_t& out_unbacked) {
    void* stack[MAX_STACK_FRAMES + 2];
    USHORT frames = RtlCaptureStackBackTrace(2, MAX_STACK_FRAMES, stack, nullptr);

    out_count = (uint8_t)((frames < MAX_STACK_FRAMES) ? frames : MAX_STACK_FRAMES);
    out_unbacked = 0;

    for (int i = 0; i < out_count; i++) {
        out_frames[i] = (uint64_t)stack[i];
        HMODULE hMod = nullptr;
        BOOL backed = GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)stack[i], &hMod);
        if (!backed)
            out_unbacked = 1;
    }
}

static PVOID NTAPI HookedAlloc(PVOID hHeap, ULONG flags, SIZE_T size) {
    PVOID ptr = OrigAlloc(hHeap, flags, size);
    if (!GetInHook() && !g_in_snapshot && ptr && g_pipe && g_pipe->IsConnected()) {
        SetInHook(true);
        AllocEventMsg msg = {};
        msg.heap_handle = (uint64_t)hHeap;
        msg.address     = (uint64_t)ptr;
        msg.size        = size;
        QueryPerformanceCounter((LARGE_INTEGER*)&msg.timestamp);
        CaptureCallstack(msg.frame_count, msg.frames, msg.unbacked);
        g_pipe->QueueEvent(MSG_ALLOC_EVENT, &msg, sizeof(msg));
        SetInHook(false);
    }
    return ptr;
}

static BOOLEAN NTAPI HookedFree(PVOID hHeap, ULONG flags, PVOID ptr) {
    if (!GetInHook() && !g_in_snapshot && ptr && g_pipe && g_pipe->IsConnected()) {
        SetInHook(true);
        FreeEventMsg msg = {};
        msg.heap_handle = (uint64_t)hHeap;
        msg.address     = (uint64_t)ptr;
        QueryPerformanceCounter((LARGE_INTEGER*)&msg.timestamp);
        g_pipe->QueueEvent(MSG_FREE_EVENT, &msg, sizeof(msg));
        SetInHook(false);
    }
    return OrigFree(hHeap, flags, ptr);
}

static PVOID NTAPI HookedReAlloc(PVOID hHeap, ULONG flags, PVOID ptr, SIZE_T size) {
    PVOID newPtr = OrigReAlloc(hHeap, flags, ptr, size);
    if (!GetInHook() && !g_in_snapshot && g_pipe && g_pipe->IsConnected()) {
        SetInHook(true);
        ReallocEventMsg msg = {};
        msg.heap_handle  = (uint64_t)hHeap;
        msg.old_address  = (uint64_t)ptr;
        msg.new_address  = (uint64_t)newPtr;
        msg.new_size     = size;
        QueryPerformanceCounter((LARGE_INTEGER*)&msg.timestamp);
        CaptureCallstack(msg.frame_count, msg.frames, msg.unbacked);
        g_pipe->QueueEvent(MSG_REALLOC_EVENT, &msg, sizeof(msg));
        SetInHook(false);
    }
    return newPtr;
}

bool Hooks::Install(PipeClient* pipe) {
    g_pipe = pipe;
    g_tls_in_hook = TlsAlloc();
    if (g_tls_in_hook == TLS_OUT_OF_INDEXES) return false;
    if (MH_Initialize() != MH_OK) return false;

    if (MH_CreateHookApi(L"ntdll", "RtlAllocateHeap",
                         (LPVOID)HookedAlloc, (LPVOID*)&OrigAlloc) != MH_OK)
        return false;
    if (MH_CreateHookApi(L"ntdll", "RtlFreeHeap",
                         (LPVOID)HookedFree, (LPVOID*)&OrigFree) != MH_OK)
        return false;
    if (MH_CreateHookApi(L"ntdll", "RtlReAllocateHeap",
                         (LPVOID)HookedReAlloc, (LPVOID*)&OrigReAlloc) != MH_OK)
        return false;

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) return false;
    g_installed = true;
    return true;
}

void Hooks::Remove() {
    if (g_installed) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        g_installed = false;
    }
    if (g_tls_in_hook != TLS_OUT_OF_INDEXES) {
        TlsFree(g_tls_in_hook);
        g_tls_in_hook = TLS_OUT_OF_INDEXES;
    }
}

bool Hooks::IsInstalled() {
    return g_installed;
}
