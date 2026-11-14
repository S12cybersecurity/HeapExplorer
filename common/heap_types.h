#pragma once
#include <cstdint>
#include <vector>
#include <string>

#define MAX_STACK_FRAMES_GUI 16

struct HeapBlock {
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

    enum State : uint8_t { UNCHANGED, NEW, FREED, MODIFIED };
    State state = UNCHANGED;
};

struct HeapInfo {
    uint64_t handle;
    uint32_t block_count;
    uint64_t total_size;
};

struct HeapEvent {
    enum Type : uint8_t { ALLOC, FREE, REALLOC };
    Type     type;
    uint64_t heap_handle;
    uint64_t address;
    uint64_t size;
    uint64_t old_address;
    uint64_t timestamp;

    bool     unbacked;
    uint8_t  frame_count;
    uint64_t frames[MAX_STACK_FRAMES_GUI];

    double   lifetime_ms;
};

struct HeapSnapshot {
    std::vector<HeapInfo>  heaps;
    std::vector<HeapBlock> blocks;
    uint64_t timestamp = 0;
};
