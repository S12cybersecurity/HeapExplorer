#pragma once
#include "pipe_server.h"
#include "common/heap_types.h"
#include <vector>
#include <deque>
#include <string>
#include <unordered_set>
#include <unordered_map>

struct ProcessEntry {
    DWORD pid;
    std::string name;
};

struct CallstackInfo {
    bool     unbacked;
    uint8_t  frame_count;
    uint64_t frames[MAX_STACK_FRAMES_GUI];
};

struct ExtractedString {
    uint64_t address;
    uint8_t  type; // 0=ASCII, 1=Unicode, 2=IOC
    std::string text;
};

struct SnapshotEntry {
    int id;
    int block_count;
    HeapSnapshot snapshot;
};

class App {
public:
    void Render();
    PipeServer& GetPipeServer() { return pipe_; }
    void AttachToPID(DWORD pid) { DoAttach(pid); }

private:
    void RenderMenuBar();
    void RenderHeapList();
    void RenderBlockBrowser();
    void RenderTimeline();
    void RenderBlockDetail();
    void RenderAllStrings();
    void RenderAttachDialog();
    void ProcessEvents();
    void DiffSnapshots();
    void RebuildStringCache();
    const HeapSnapshot& GetDisplaySnapshot() const;

    void DoOpenFile();
    void DoAttach(DWORD pid);
    void RefreshProcessList();
    void SetStatus(const std::string& msg, bool isError = false);

    static const char* PermissionStr(uint32_t prot);
    static std::vector<std::string> ExtractAsciiStrings(const uint8_t* data,
                                                         size_t len, size_t min_len = 6);
    static std::vector<std::string> ExtractUnicodeStrings(const uint8_t* data,
                                                           size_t len, size_t min_len = 4);
    static std::vector<std::string> ExtractIOCs(const uint8_t* data, size_t len);

    PipeServer pipe_;

    HeapSnapshot current_snapshot_;
    HeapSnapshot prev_snapshot_;
    std::deque<HeapEvent> event_log_;

    int  selected_heap_  = -1;
    int  selected_block_ = -1;
    bool auto_refresh_     = false;
    float refresh_interval_ = 1.0f;
    float refresh_timer_    = 0.0f;
    bool hooks_enabled_ = true;
    bool show_freed_    = true;

    char     filter_addr_[32] = {};
    uint64_t filter_min_size_ = 0;
    bool     filter_suspicious_ = false;

    std::unordered_map<uint64_t, uint32_t> prev_block_hashes_;

    bool show_attach_ = false;
    std::vector<ProcessEntry> process_list_;
    char process_filter_[128] = {};

    std::string status_msg_;
    bool status_is_error_ = false;
    float status_timer_ = 0;

    std::vector<ExtractedString> cached_strings_;
    char strings_filter_[128] = {};

    std::unordered_map<uint64_t, uint64_t> alloc_timestamps_;
    std::unordered_map<uint64_t, CallstackInfo> callstack_cache_;
    LARGE_INTEGER qpc_freq_ = {};
    bool qpc_init_ = false;

    std::vector<SnapshotEntry> snapshot_history_;
    int selected_snapshot_ = -1;
    int next_snapshot_id_  = 1;
    int prev_selected_snap_ = -1;
};
