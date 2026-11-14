#pragma once
#include <cstdint>

#define HEAPEX_PIPE_NAME L"\\\\.\\pipe\\HeapExplorer"
#define MAX_STACK_FRAMES 16

enum MessageType : uint32_t {
    MSG_WORKER_READY     = 0x0001,
    MSG_SNAPSHOT_REQUEST = 0x0010,
    MSG_SNAPSHOT_BEGIN   = 0x0011,
    MSG_SNAPSHOT_BLOCK   = 0x0012,
    MSG_SNAPSHOT_END     = 0x0013,
    MSG_ALLOC_EVENT      = 0x0020,
    MSG_FREE_EVENT       = 0x0021,
    MSG_REALLOC_EVENT    = 0x0022,
    MSG_HOOKS_ENABLE     = 0x0030,
    MSG_HOOKS_DISABLE    = 0x0031,
};

enum BlockClass : uint32_t {
    BLK_NONE             = 0,
    BLK_PE_HEADER        = (1 << 0),
    BLK_SHELLCODE        = (1 << 1),
    BLK_ENCRYPTED        = (1 << 2),
    BLK_UNICODE_STR      = (1 << 3),
    BLK_INJECTED_PAGE    = (1 << 4),
    BLK_EMBEDDED_PE      = (1 << 5),
    BLK_HIGH_ENTROPY     = (1 << 6),
    BLK_EXECUTABLE       = (1 << 7),
};

#pragma pack(push, 1)

struct MessageHeader {
    uint32_t size;
    uint32_t type;
};

struct WorkerReadyMsg {
    uint32_t pid;
    uint32_t heap_count;
};

struct SnapshotBlockMsg {
    uint64_t heap_handle;
    uint64_t address;
    uint64_t size;
    uint32_t flags;
    double   entropy;
    uint32_t permissions;
    uint32_t content_hash;
    uint32_t classification;
    uint16_t preview_size;
    uint8_t  preview[256];
};

struct SnapshotEndMsg {
    uint32_t total_blocks;
    uint32_t total_heaps;
};

struct AllocEventMsg {
    uint64_t heap_handle;
    uint64_t address;
    uint64_t size;
    uint64_t timestamp;
    uint8_t  unbacked;
    uint8_t  frame_count;
    uint8_t  _pad[6];
    uint64_t frames[MAX_STACK_FRAMES];
};

struct FreeEventMsg {
    uint64_t heap_handle;
    uint64_t address;
    uint64_t timestamp;
};

struct ReallocEventMsg {
    uint64_t heap_handle;
    uint64_t old_address;
    uint64_t new_address;
    uint64_t new_size;
    uint64_t timestamp;
    uint8_t  unbacked;
    uint8_t  frame_count;
    uint8_t  _pad[6];
    uint64_t frames[MAX_STACK_FRAMES];
};

#pragma pack(pop)
