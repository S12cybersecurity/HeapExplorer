#include "snapshot.h"
#include "pipe_client.h"
#include "common/protocol.h"
#include <Windows.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <vector>

static double ShannonEntropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    int freq[256] = {};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        entropy -= p * log2(p);
    }
    return entropy;
}

static uint32_t FNV1a(const uint8_t* data, size_t len) {
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x01000193;
    }
    return h;
}

static uint32_t ClassifyBlock(const uint8_t* data, size_t data_len,
                               size_t block_size, double entropy, uint32_t perms) {
    uint32_t cls = BLK_NONE;

    if (data_len >= 2 && data[0] == 0x4D && data[1] == 0x5A)
        cls |= BLK_PE_HEADER;

    if (data_len >= 4) {
        if (data[0] == 0x48 && data[1] == 0x83 && data[2] == 0xEC)
            cls |= BLK_SHELLCODE;
        if (data[0] == 0xFC)
            cls |= BLK_SHELLCODE;
        if (data[0] == 0x55 && data[1] == 0x48 && data[2] == 0x89 && data[3] == 0xE5)
            cls |= BLK_SHELLCODE;
        if (data[0] == 0x48 && data[1] == 0x89 && data[2] == 0x5C && data[3] == 0x24)
            cls |= BLK_SHELLCODE;
    }

    if (entropy > 7.0) {
        cls |= BLK_HIGH_ENTROPY;
        if (block_size >= 16 && (block_size % 16) == 0)
            cls |= BLK_ENCRYPTED;
    }

    if (data_len >= 8) {
        int null_pattern = 0;
        size_t check = (data_len < 32) ? data_len : 32;
        for (size_t i = 1; i < check; i += 2) {
            if (data[i] == 0 && data[i - 1] >= 0x20 && data[i - 1] < 0x7F)
                null_pattern++;
        }
        if (null_pattern >= 3)
            cls |= BLK_UNICODE_STR;
    }

    if (block_size >= 0x1000 && (block_size & 0xFFF) == 0)
        cls |= BLK_INJECTED_PAGE;

    size_t scan_len = (data_len < 256) ? data_len : 256;
    if (scan_len >= 80) {
        for (size_t i = 0; i + 19 <= scan_len; i++) {
            if (memcmp(data + i, "This program cannot", 19) == 0) {
                cls |= BLK_EMBEDDED_PE;
                break;
            }
        }
    }

    if (perms & 0xF0)
        cls |= BLK_EXECUTABLE;

    return cls;
}

struct RawBlock {
    uint64_t heap;
    uint64_t address;
    uint64_t size;
    uint32_t flags;
    uint16_t preview_size;
    uint8_t  preview[256];
};

static bool SafeMemcpy(void* dst, const void* src, size_t len) {
    __try {
        memcpy(dst, src, len);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool SafeAnalyze(const uint8_t* data, size_t len,
                         double* out_entropy, uint32_t* out_hash) {
    __try {
        *out_entropy = ShannonEntropy(data, len);
        *out_hash    = FNV1a(data, len);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

volatile bool g_in_snapshot = false;

void Snapshot::Take(PipeClient& pipe) {
    g_in_snapshot = true;
    pipe.Send(MSG_SNAPSHOT_BEGIN, nullptr, 0);

    HANDLE heaps[256];
    DWORD count = GetProcessHeaps(256, heaps);
    uint32_t total_blocks = 0;

    for (DWORD i = 0; i < count; i++) {
        // Phase 1: fast collection under HeapLock — only copy addresses + 256B preview
        std::vector<RawBlock> collected;
        collected.reserve(4096);

        if (!HeapLock(heaps[i])) continue;

        PROCESS_HEAP_ENTRY entry = {};
        while (HeapWalk(heaps[i], &entry)) {
            if (!(entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)) continue;

            RawBlock rb = {};
            rb.heap    = (uint64_t)heaps[i];
            rb.address = (uint64_t)entry.lpData;
            rb.size    = entry.cbData;
            rb.flags   = entry.wFlags;
            rb.preview_size = (uint16_t)((entry.cbData < 256) ? entry.cbData : 256);
            if (!SafeMemcpy(rb.preview, entry.lpData, rb.preview_size))
                rb.preview_size = 0;
            collected.push_back(rb);
        }
        HeapUnlock(heaps[i]);

        // Phase 2: analysis + send with NO heap lock held
        for (auto& rb : collected) {
            SnapshotBlockMsg blk = {};
            blk.heap_handle  = rb.heap;
            blk.address      = rb.address;
            blk.size         = rb.size;
            blk.flags        = rb.flags;
            blk.preview_size = rb.preview_size;
            memcpy(blk.preview, rb.preview, rb.preview_size);

            SIZE_T analysis_len = (rb.size < 4096) ? (SIZE_T)rb.size : 4096;
            const uint8_t* live = (const uint8_t*)(uintptr_t)rb.address;
            if (!SafeAnalyze(live, analysis_len, &blk.entropy, &blk.content_hash)) {
                blk.entropy      = ShannonEntropy(rb.preview, rb.preview_size);
                blk.content_hash = FNV1a(rb.preview, rb.preview_size);
            }

            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery((void*)(uintptr_t)rb.address, &mbi, sizeof(mbi)))
                blk.permissions = mbi.Protect;

            blk.classification = ClassifyBlock(blk.preview, blk.preview_size,
                                                (size_t)rb.size, blk.entropy,
                                                blk.permissions);

            pipe.Send(MSG_SNAPSHOT_BLOCK, &blk, sizeof(blk));
            total_blocks++;
        }
    }

    SnapshotEndMsg end_msg = {};
    end_msg.total_blocks = total_blocks;
    end_msg.total_heaps  = count;
    pipe.Send(MSG_SNAPSHOT_END, &end_msg, sizeof(end_msg));
    g_in_snapshot = false;
}
