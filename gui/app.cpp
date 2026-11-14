#include "app.h"
#include "injector.h"
#include "common/protocol.h"
#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <commdlg.h>
#include <TlHelp32.h>

#pragma comment(lib, "comdlg32.lib")

static const ImVec4 COL_GREEN  = {0.2f, 1.0f, 0.3f, 1.0f};
static const ImVec4 COL_RED    = {1.0f, 0.3f, 0.3f, 1.0f};
static const ImVec4 COL_YELLOW = {1.0f, 1.0f, 0.3f, 1.0f};
static const ImVec4 COL_WHITE  = {1.0f, 1.0f, 1.0f, 1.0f};
static const ImVec4 COL_DIM    = {0.5f, 0.5f, 0.5f, 1.0f};
static const ImVec4 COL_ORANGE = {1.0f, 0.6f, 0.2f, 1.0f};
static const ImVec4 COL_PURPLE = {0.8f, 0.4f, 1.0f, 1.0f};
static const ImVec4 COL_CYAN   = {0.3f, 0.9f, 1.0f, 1.0f};

static ImVec4 EntropyColor(double e) {
    if (e < 3.5)  return COL_GREEN;
    if (e < 6.0)  return COL_YELLOW;
    if (e < 7.0)  return COL_ORANGE;
    return COL_RED;
}

const char* App::PermissionStr(uint32_t prot) {
    switch (prot & 0xFF) {
    case 0x01: return "---";
    case 0x02: return "R--";
    case 0x04: return "RW-";
    case 0x08: return "RWC";
    case 0x10: return "--X";
    case 0x20: return "R-X";
    case 0x40: return "RWX";
    case 0x80: return "RXC";
    default:   return "???";
    }
}

std::vector<std::string> App::ExtractAsciiStrings(const uint8_t* data, size_t len,
                                                   size_t min_len) {
    std::vector<std::string> result;
    std::string cur;
    for (size_t i = 0; i < len; i++) {
        if (data[i] >= 0x20 && data[i] < 0x7F) {
            cur += (char)data[i];
        } else {
            if (cur.size() >= min_len)
                result.push_back(cur);
            cur.clear();
        }
    }
    if (cur.size() >= min_len)
        result.push_back(cur);
    return result;
}

std::vector<std::string> App::ExtractUnicodeStrings(const uint8_t* data, size_t len,
                                                     size_t min_len) {
    std::vector<std::string> result;
    std::string cur;
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint8_t lo = data[i];
        uint8_t hi = data[i + 1];
        if (hi == 0 && lo >= 0x20 && lo < 0x7F) {
            cur += (char)lo;
        } else {
            if (cur.size() >= min_len)
                result.push_back(cur);
            cur.clear();
        }
    }
    if (cur.size() >= min_len)
        result.push_back(cur);
    return result;
}

static bool IsDigit(char c) { return c >= '0' && c <= '9'; }
static bool IsHex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

std::vector<std::string> App::ExtractIOCs(const uint8_t* data, size_t len) {
    std::vector<std::string> iocs;
    std::string buf;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        if (c >= 0x20 && c < 0x7F)
            buf += (char)c;
        else {
            buf += '\0';
        }
    }
    buf += '\0';

    auto scan = [&](const char* prefix) -> bool {
        return buf.find(prefix) != std::string::npos;
    };

    // IP addresses: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
    for (size_t i = 0; i + 6 < buf.size(); i++) {
        if (!IsDigit(buf[i])) continue;
        int dots = 0, digits = 0, start = (int)i;
        size_t j = i;
        while (j < buf.size() && (IsDigit(buf[j]) || buf[j] == '.')) {
            if (buf[j] == '.') { dots++; digits = 0; }
            else digits++;
            if (digits > 3) break;
            j++;
        }
        if (dots == 3 && j > i + 6) {
            std::string ip = buf.substr(i, j - i);
            if (ip.back() != '.')
                iocs.push_back("IP: " + ip);
            i = j;
        }
    }

    // URLs
    for (auto prefix : {"http://", "https://"}) {
        size_t pos = 0;
        while ((pos = buf.find(prefix, pos)) != std::string::npos) {
            size_t end = pos;
            while (end < buf.size() && buf[end] >= 0x21 && buf[end] < 0x7F)
                end++;
            iocs.push_back("URL: " + buf.substr(pos, end - pos));
            pos = end;
        }
    }

    // Named pipes
    {
        size_t pos = 0;
        while ((pos = buf.find("\\\\.\\pipe\\", pos)) != std::string::npos) {
            size_t end = pos + 9;
            while (end < buf.size() && buf[end] > 0x20 && buf[end] < 0x7F)
                end++;
            iocs.push_back("PIPE: " + buf.substr(pos, end - pos));
            pos = end;
        }
    }

    // UUIDs: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    for (size_t i = 0; i + 35 < buf.size(); i++) {
        if (!IsHex(buf[i])) continue;
        bool valid = true;
        int dashes[] = {8, 13, 18, 23};
        for (int d : dashes) {
            if (i + d >= buf.size() || buf[i + d] != '-') { valid = false; break; }
        }
        if (!valid) continue;
        bool all_hex = true;
        for (int k = 0; k < 36; k++) {
            if (k == 8 || k == 13 || k == 18 || k == 23) continue;
            if (!IsHex(buf[i + k])) { all_hex = false; break; }
        }
        if (all_hex) {
            iocs.push_back("UUID: " + buf.substr(i, 36));
            i += 36;
        }
    }

    // Registry keys
    for (auto prefix : {"HKEY_", "SOFTWARE\\", "HKLM\\", "HKCU\\"}) {
        size_t pos = 0;
        while ((pos = buf.find(prefix, pos)) != std::string::npos) {
            size_t end = pos;
            while (end < buf.size() && buf[end] > 0x20 && buf[end] < 0x7F)
                end++;
            if (end - pos > 6)
                iocs.push_back("REG: " + buf.substr(pos, end - pos));
            pos = end;
        }
    }

    // Mutex patterns: common mutex-like names
    for (auto prefix : {"Global\\", "Local\\"}) {
        size_t pos = 0;
        while ((pos = buf.find(prefix, pos)) != std::string::npos) {
            size_t end = pos;
            while (end < buf.size() && buf[end] > 0x20 && buf[end] < 0x7F)
                end++;
            if (end - pos > 8)
                iocs.push_back("MUTEX: " + buf.substr(pos, end - pos));
            pos = end;
        }
    }

    return iocs;
}

void App::SetStatus(const std::string& msg, bool isError) {
    status_msg_ = msg;
    status_is_error_ = isError;
    status_timer_ = 6.0f;
}

const HeapSnapshot& App::GetDisplaySnapshot() const {
    if (selected_snapshot_ >= 0 &&
        selected_snapshot_ < (int)snapshot_history_.size())
        return snapshot_history_[selected_snapshot_].snapshot;
    return current_snapshot_;
}

void App::DoOpenFile() {
    char filename[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = "Executables\0*.exe\0All Files\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrTitle = "Select target executable";

    if (!GetOpenFileNameA(&ofn)) return;

    if (!pipe_.IsRunning()) pipe_.Restart();
    else if (pipe_.IsConnected()) pipe_.Restart();

    auto r = Injector::LaunchAndInject(filename);
    if (r.success)
        SetStatus("Launched PID " + std::to_string(r.pid));
    else
        SetStatus(r.error, true);
}

void App::DoAttach(DWORD pid) {
    if (!pipe_.IsRunning()) pipe_.Restart();
    else if (pipe_.IsConnected()) pipe_.Restart();

    auto r = Injector::AttachToProcess(pid);
    if (r.success) {
        SetStatus("Attached to PID " + std::to_string(r.pid));
        show_attach_ = false;
    } else {
        SetStatus(r.error, true);
    }
}

void App::RefreshProcessList() {
    process_list_.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            ProcessEntry entry;
            entry.pid = pe.th32ProcessID;
            char name[260];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                name, sizeof(name), NULL, NULL);
            entry.name = name;
            process_list_.push_back(entry);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    std::sort(process_list_.begin(), process_list_.end(),
              [](const ProcessEntry& a, const ProcessEntry& b) {
                  return a.name < b.name;
              });
}

void App::Render() {
    if (!qpc_init_) {
        QueryPerformanceFrequency(&qpc_freq_);
        qpc_init_ = true;
    }

    ProcessEvents();

    if (auto_refresh_) {
        refresh_timer_ += ImGui::GetIO().DeltaTime;
        if (refresh_timer_ >= refresh_interval_) {
            refresh_timer_ = 0;
            pipe_.SendCommand(MSG_SNAPSHOT_REQUEST);
        }
    }

    if (pipe_.HasNewSnapshot()) {
        if (!current_snapshot_.blocks.empty()) {
            SnapshotEntry entry;
            entry.id = next_snapshot_id_++;
            entry.block_count = (int)current_snapshot_.blocks.size();
            entry.snapshot = current_snapshot_;
            snapshot_history_.push_back(std::move(entry));
            if (snapshot_history_.size() > 50)
                snapshot_history_.erase(snapshot_history_.begin());
        }
        prev_snapshot_ = std::move(current_snapshot_);
        current_snapshot_ = pipe_.TakeSnapshot();
        DiffSnapshots();
        if (selected_snapshot_ < 0)
            RebuildStringCache();
    }

    if (selected_snapshot_ != prev_selected_snap_) {
        selected_block_ = -1;
        RebuildStringCache();
        prev_selected_snap_ = selected_snapshot_;
    }

    if (ImGui::IsKeyPressed(ImGuiKey_F5) && pipe_.IsConnected())
        pipe_.SendCommand(MSG_SNAPSHOT_REQUEST);

    if (status_timer_ > 0)
        status_timer_ -= ImGui::GetIO().DeltaTime;

    RenderMenuBar();

    if (show_attach_)
        RenderAttachDialog();

    ImVec2 ds = ImGui::GetIO().DisplaySize;
    float menu_h = ImGui::GetFrameHeight();
    float w = ds.x;
    float h = ds.y - menu_h;
    float y0 = menu_h;

    float left_w  = w * 0.18f;
    float right_w = w * 0.28f;
    float mid_w   = w - left_w - right_w;
    float top_h   = h * 0.62f;
    float bot_h   = h - top_h;

    ImGui::SetNextWindowPos(ImVec2(0, y0));
    ImGui::SetNextWindowSize(ImVec2(left_w, top_h));
    RenderHeapList();

    ImGui::SetNextWindowPos(ImVec2(left_w, y0));
    ImGui::SetNextWindowSize(ImVec2(mid_w, top_h));
    RenderBlockBrowser();

    ImGui::SetNextWindowPos(ImVec2(0, y0 + top_h));
    ImGui::SetNextWindowSize(ImVec2(left_w + mid_w, bot_h));
    ImGui::Begin("##bottom", nullptr,
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoTitleBar);
    if (ImGui::BeginTabBar("BottomTabs")) {
        if (ImGui::BeginTabItem("Event Timeline")) {
            RenderTimeline();
            ImGui::EndTabItem();
        }
        char str_tab[64];
        snprintf(str_tab, sizeof(str_tab), "All Strings (%zu)###strings",
                 cached_strings_.size());
        if (ImGui::BeginTabItem(str_tab)) {
            RenderAllStrings();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(left_w + mid_w, y0));
    ImGui::SetNextWindowSize(ImVec2(right_w, h));
    RenderBlockDetail();
}

void App::ProcessEvents() {
    HeapEvent evt;
    int processed = 0;
    while (processed < 2000 && pipe_.PopEvent(evt)) {
        if (evt.type == HeapEvent::ALLOC) {
            alloc_timestamps_[evt.address] = evt.timestamp;
            CallstackInfo ci = {};
            ci.unbacked = evt.unbacked;
            ci.frame_count = evt.frame_count;
            for (int i = 0; i < evt.frame_count; i++)
                ci.frames[i] = evt.frames[i];
            callstack_cache_[evt.address] = ci;
        } else if (evt.type == HeapEvent::FREE) {
            auto it = alloc_timestamps_.find(evt.address);
            if (it != alloc_timestamps_.end() && qpc_freq_.QuadPart > 0) {
                int64_t delta = (int64_t)evt.timestamp - (int64_t)it->second;
                evt.lifetime_ms = (double)delta * 1000.0 / (double)qpc_freq_.QuadPart;
                alloc_timestamps_.erase(it);
            }
            callstack_cache_.erase(evt.address);
        } else if (evt.type == HeapEvent::REALLOC) {
            alloc_timestamps_.erase(evt.old_address);
            alloc_timestamps_[evt.address] = evt.timestamp;
            CallstackInfo ci = {};
            ci.unbacked = evt.unbacked;
            ci.frame_count = evt.frame_count;
            for (int i = 0; i < evt.frame_count; i++)
                ci.frames[i] = evt.frames[i];
            callstack_cache_.erase(evt.old_address);
            callstack_cache_[evt.address] = ci;
        }

        event_log_.push_back(evt);
        while (event_log_.size() > 50000)
            event_log_.pop_front();
        processed++;
    }
}

void App::DiffSnapshots() {
    std::unordered_map<uint64_t, uint32_t> prev_hashes;
    for (auto& b : prev_snapshot_.blocks)
        prev_hashes[b.address] = b.content_hash;

    for (auto& b : current_snapshot_.blocks) {
        auto it = prev_hashes.find(b.address);
        if (it == prev_hashes.end())
            b.state = HeapBlock::NEW;
        else if (it->second != b.content_hash)
            b.state = HeapBlock::MODIFIED;
        else
            b.state = HeapBlock::UNCHANGED;
    }

    prev_block_hashes_.clear();
    for (auto& b : current_snapshot_.blocks)
        prev_block_hashes_[b.address] = b.content_hash;
}

void App::RenderMenuBar() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open File...", "Ctrl+O"))
                DoOpenFile();
            if (ImGui::MenuItem("Attach to Process...", "Ctrl+A")) {
                show_attach_ = true;
                RefreshProcessList();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit"))
                PostQuitMessage(0);
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Control")) {
            if (ImGui::MenuItem("Take Snapshot (F5)", nullptr, false,
                                pipe_.IsConnected()))
                pipe_.SendCommand(MSG_SNAPSHOT_REQUEST);

            ImGui::Separator();
            ImGui::Checkbox("Auto Refresh", &auto_refresh_);
            if (auto_refresh_)
                ImGui::SliderFloat("Interval (s)", &refresh_interval_,
                                   0.1f, 10.0f);

            ImGui::Separator();
            if (ImGui::MenuItem("Hooks Enabled", nullptr, hooks_enabled_,
                                pipe_.IsConnected())) {
                hooks_enabled_ = !hooks_enabled_;
                pipe_.SendCommand(hooks_enabled_ ? MSG_HOOKS_ENABLE
                                                 : MSG_HOOKS_DISABLE);
            }
            ImGui::EndMenu();
        }

        ImGui::Separator();

        if (pipe_.IsConnected()) {
            ImGui::TextColored(COL_GREEN, " CONNECTED (PID %u)",
                               pipe_.WorkerPID());
            ImGui::SameLine();

            const auto& disp = GetDisplaySnapshot();
            int suspicious = 0;
            for (auto& b : disp.blocks) {
                if (b.classification & (BLK_PE_HEADER | BLK_SHELLCODE |
                    BLK_ENCRYPTED | BLK_EXECUTABLE | BLK_EMBEDDED_PE))
                    suspicious++;
            }

            ImGui::Text("Blocks: %zu  Events: %zu",
                        disp.blocks.size(), event_log_.size());
            if (selected_snapshot_ >= 0 &&
                selected_snapshot_ < (int)snapshot_history_.size()) {
                ImGui::SameLine();
                ImGui::TextColored(COL_CYAN, "  [Snapshot #%d]",
                                   snapshot_history_[selected_snapshot_].id);
            }
            if (suspicious > 0) {
                ImGui::SameLine();
                ImGui::TextColored(COL_RED, "  SUSPICIOUS: %d", suspicious);
            }
        } else {
            ImGui::TextColored(COL_DIM, " Not connected  ");
            ImGui::SameLine();
            ImGui::TextDisabled("File > Open or Attach");
        }

        if (status_timer_ > 0) {
            ImGui::SameLine();
            ImGui::Text("  |  ");
            ImGui::SameLine();
            ImGui::TextColored(status_is_error_ ? COL_RED : COL_GREEN,
                               "%s", status_msg_.c_str());
        }

        ImGui::EndMainMenuBar();
    }

    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O))
        DoOpenFile();
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A)) {
        show_attach_ = true;
        RefreshProcessList();
    }
}

void App::RenderAttachDialog() {
    ImGui::SetNextWindowSize(ImVec2(500, 420), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Attach to Process", &show_attach_)) {
        ImGui::End();
        return;
    }

    if (ImGui::Button("Refresh"))
        RefreshProcessList();
    ImGui::SameLine();
    ImGui::InputText("Filter", process_filter_, sizeof(process_filter_));

    ImGui::Separator();

    if (ImGui::BeginTable("procs", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
            ImVec2(0, -30))) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PID",  0, 70.0f);
        ImGui::TableSetupColumn("Name", 0, 280.0f);
        ImGui::TableSetupColumn("",     0, 70.0f);
        ImGui::TableHeadersRow();

        for (auto& p : process_list_) {
            if (process_filter_[0]) {
                if (p.name.find(process_filter_) == std::string::npos)
                    continue;
            }
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%u", p.pid);
            ImGui::TableNextColumn();
            ImGui::Text("%s", p.name.c_str());
            ImGui::TableNextColumn();
            char btn_id[32];
            snprintf(btn_id, sizeof(btn_id), "Inject##%u", p.pid);
            if (ImGui::SmallButton(btn_id))
                DoAttach(p.pid);
        }
        ImGui::EndTable();
    }

    ImGui::End();
}

void App::RenderHeapList() {
    ImGui::Begin("Heaps", nullptr,
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoCollapse);

    if (!snapshot_history_.empty()) {
        ImGui::TextColored(COL_CYAN, "Snapshots");
        ImGui::Separator();

        bool is_live = (selected_snapshot_ < 0);
        if (ImGui::Selectable("(Live - diff view)", is_live))
            selected_snapshot_ = -1;

        for (int i = 0; i < (int)snapshot_history_.size(); i++) {
            auto& e = snapshot_history_[i];
            char label[64];
            snprintf(label, sizeof(label), "#%d  %d blocks", e.id, e.block_count);
            if (ImGui::Selectable(label, selected_snapshot_ == i))
                selected_snapshot_ = i;
        }

        ImGui::Spacing();
    }

    ImGui::TextColored(COL_CYAN, "Heaps");
    ImGui::Separator();

    const auto& snap = GetDisplaySnapshot();
    if (snap.heaps.empty()) {
        ImGui::TextDisabled("No heap data yet.");
    } else {
        if (ImGui::Selectable("(all heaps)", selected_heap_ == -1))
            selected_heap_ = -1;

        for (int i = 0; i < (int)snap.heaps.size(); i++) {
            auto& h = snap.heaps[i];
            char label[128];
            snprintf(label, sizeof(label),
                     "0x%llX  %u blk  %.1f KB",
                     (unsigned long long)h.handle,
                     h.block_count,
                     h.total_size / 1024.0);
            if (ImGui::Selectable(label, selected_heap_ == i))
                selected_heap_ = i;
        }
    }
    ImGui::End();
}

void App::RenderBlockBrowser() {
    ImGui::Begin("Block Browser", nullptr,
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoCollapse);

    ImGui::InputText("Addr filter", filter_addr_, sizeof(filter_addr_));
    ImGui::SameLine();
    ImGui::Checkbox("Freed", &show_freed_);
    ImGui::SameLine();
    ImGui::Checkbox("Suspicious only", &filter_suspicious_);
    ImGui::Separator();

    // Build visible block indices with substring address filter
    std::vector<int> visible;
    char filter_upper[32] = {};
    bool has_filter = (filter_addr_[0] != '\0');
    if (has_filter) {
        const char* src = filter_addr_;
        if (src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) src += 2;
        for (int k = 0; src[k] && k < 31; k++)
            filter_upper[k] = (char)toupper((unsigned char)src[k]);
    }

    const auto& snap = GetDisplaySnapshot();
    bool live_view = (selected_snapshot_ < 0);

    for (int i = 0; i < (int)snap.blocks.size(); i++) {
        auto& blk = snap.blocks[i];

        if (selected_heap_ >= 0 &&
            selected_heap_ < (int)snap.heaps.size()) {
            if (blk.heap_handle !=
                snap.heaps[selected_heap_].handle)
                continue;
        }

        if (has_filter) {
            char addr_hex[20];
            snprintf(addr_hex, sizeof(addr_hex), "%llX",
                     (unsigned long long)blk.address);
            if (!strstr(addr_hex, filter_upper)) continue;
        }

        if (!show_freed_ && blk.state == HeapBlock::FREED) continue;

        if (filter_suspicious_) {
            if (!(blk.classification & (BLK_PE_HEADER | BLK_SHELLCODE |
                  BLK_ENCRYPTED | BLK_EXECUTABLE | BLK_EMBEDDED_PE |
                  BLK_HIGH_ENTROPY)))
                continue;
        }

        visible.push_back(i);
    }

    ImGuiTableFlags tflags = ImGuiTableFlags_Borders |
                             ImGuiTableFlags_RowBg |
                             ImGuiTableFlags_Resizable |
                             ImGuiTableFlags_ScrollY |
                             ImGuiTableFlags_SizingFixedFit |
                             ImGuiTableFlags_Sortable |
                             ImGuiTableFlags_SortTristate;

    if (ImGui::BeginTable("blocks", 7, tflags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address",  ImGuiTableColumnFlags_DefaultSort, 130.0f);
        ImGui::TableSetupColumn("Size",     0, 70.0f);
        ImGui::TableSetupColumn("Entropy",  0, 55.0f);
        ImGui::TableSetupColumn("Perm",     0, 35.0f);
        ImGui::TableSetupColumn("Class",    0, 100.0f);
        ImGui::TableSetupColumn("State",    0, 40.0f);
        ImGui::TableSetupColumn("Preview",  ImGuiTableColumnFlags_NoSort, 120.0f);
        ImGui::TableHeadersRow();

        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs()) {
            if (specs->SpecsCount > 0) {
                const auto& spec = specs->Specs[0];
                int col = spec.ColumnIndex;
                bool asc = (spec.SortDirection == ImGuiSortDirection_Ascending);
                auto& blocks = snap.blocks;
                std::sort(visible.begin(), visible.end(),
                    [&](int a, int b) {
                        const auto& ba = blocks[a];
                        const auto& bb = blocks[b];
                        int cmp = 0;
                        switch (col) {
                        case 0: cmp = (ba.address < bb.address) ? -1 : (ba.address > bb.address) ? 1 : 0; break;
                        case 1: cmp = (ba.size < bb.size) ? -1 : (ba.size > bb.size) ? 1 : 0; break;
                        case 2: cmp = (ba.entropy < bb.entropy) ? -1 : (ba.entropy > bb.entropy) ? 1 : 0; break;
                        case 3: cmp = (int)(ba.permissions & 0xFF) - (int)(bb.permissions & 0xFF); break;
                        case 4: cmp = (ba.classification < bb.classification) ? -1 : (ba.classification > bb.classification) ? 1 : 0; break;
                        case 5: cmp = (int)ba.state - (int)bb.state; break;
                        default: break;
                        }
                        return asc ? (cmp < 0) : (cmp > 0);
                    });
            }
            specs->SpecsDirty = false;
        }

        bool scroll_to_selected = false;
        if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) ||
                ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
                int cur_pos = -1;
                for (int vi = 0; vi < (int)visible.size(); vi++) {
                    if (visible[vi] == selected_block_) { cur_pos = vi; break; }
                }
                if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
                    if (cur_pos >= 0 && cur_pos < (int)visible.size() - 1)
                        selected_block_ = visible[cur_pos + 1];
                    else if (cur_pos < 0 && !visible.empty())
                        selected_block_ = visible[0];
                } else {
                    if (cur_pos > 0)
                        selected_block_ = visible[cur_pos - 1];
                    else if (cur_pos < 0 && !visible.empty())
                        selected_block_ = visible.back();
                }
                scroll_to_selected = true;
            }
        }

        for (int vi = 0; vi < (int)visible.size(); vi++) {
            int i = visible[vi];
            auto& blk = snap.blocks[i];

            ImVec4 row_color = COL_WHITE;
            const char* state_str = "-";
            if (live_view) {
                switch (blk.state) {
                case HeapBlock::NEW:
                    row_color = COL_GREEN;  state_str = "NEW"; break;
                case HeapBlock::FREED:
                    row_color = COL_RED;    state_str = "FRE"; break;
                case HeapBlock::MODIFIED:
                    row_color = COL_YELLOW; state_str = "MOD"; break;
                default: break;
                }
            }

            if (blk.classification & (BLK_PE_HEADER | BLK_SHELLCODE |
                BLK_EXECUTABLE | BLK_EMBEDDED_PE))
                row_color = COL_RED;

            ImGui::TableNextRow();
            ImGui::PushStyleColor(ImGuiCol_Text, row_color);

            ImGui::TableNextColumn();
            char addr_str[20];
            snprintf(addr_str, sizeof(addr_str), "0x%llX",
                     (unsigned long long)blk.address);
            if (ImGui::Selectable(addr_str, selected_block_ == i,
                                   ImGuiSelectableFlags_SpanAllColumns))
                selected_block_ = i;

            if (scroll_to_selected && selected_block_ == i)
                ImGui::SetScrollHereY();

            ImGui::TableNextColumn();
            if (blk.size >= 1024)
                ImGui::Text("%.1fK", blk.size / 1024.0);
            else
                ImGui::Text("%lluB", (unsigned long long)blk.size);

            ImGui::TableNextColumn();
            ImGui::TextColored(EntropyColor(blk.entropy), "%.1f", blk.entropy);

            ImGui::TableNextColumn();
            if (blk.permissions & 0xF0)
                ImGui::TextColored(COL_RED, "%s", PermissionStr(blk.permissions));
            else
                ImGui::Text("%s", PermissionStr(blk.permissions));

            ImGui::TableNextColumn();
            {
                char cls[64] = {};
                int len = 0;
                uint32_t c = blk.classification;
                if (c & BLK_PE_HEADER)    len += snprintf(cls+len, sizeof(cls)-len, "PE ");
                if (c & BLK_SHELLCODE)    len += snprintf(cls+len, sizeof(cls)-len, "SC ");
                if (c & BLK_ENCRYPTED)    len += snprintf(cls+len, sizeof(cls)-len, "ENC ");
                if (c & BLK_EXECUTABLE)   len += snprintf(cls+len, sizeof(cls)-len, "X ");
                if (c & BLK_EMBEDDED_PE)  len += snprintf(cls+len, sizeof(cls)-len, "EPE ");
                if (c & BLK_HIGH_ENTROPY) len += snprintf(cls+len, sizeof(cls)-len, "HE ");
                if (c & BLK_INJECTED_PAGE)len += snprintf(cls+len, sizeof(cls)-len, "PG ");
                if (c & BLK_UNICODE_STR)  len += snprintf(cls+len, sizeof(cls)-len, "U ");
                if (len == 0) strcpy(cls, "-");
                ImGui::TextUnformatted(cls);
            }

            ImGui::TableNextColumn();
            ImGui::Text("%s", state_str);

            ImGui::TableNextColumn();
            {
                char hex[48] = {};
                int len = 0;
                int n = (int)((blk.preview_size < 8) ? blk.preview_size : 8);
                for (int j = 0; j < n; j++)
                    len += snprintf(hex + len, sizeof(hex) - len,
                                    "%02X ", blk.preview[j]);
                ImGui::TextUnformatted(hex);
            }

            ImGui::PopStyleColor();
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

void App::RenderTimeline() {
    if (ImGui::Button("Clear")) {
        event_log_.clear();
        alloc_timestamps_.clear();
        callstack_cache_.clear();
    }
    ImGui::SameLine();
    ImGui::Text("(%zu events)", event_log_.size());
    ImGui::Separator();

    if (ImGui::BeginTable("events", 7,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Type",     0, 55.0f);
        ImGui::TableSetupColumn("Address",  0, 120.0f);
        ImGui::TableSetupColumn("Size",     0, 70.0f);
        ImGui::TableSetupColumn("Heap",     0, 120.0f);
        ImGui::TableSetupColumn("Unbacked", 0, 30.0f);
        ImGui::TableSetupColumn("Stack",    0, 30.0f);
        ImGui::TableSetupColumn("Lifetime", 0, 70.0f);
        ImGui::TableHeadersRow();

        int start = (int)event_log_.size() - 500;
        if (start < 0) start = 0;
        for (int i = (int)event_log_.size() - 1; i >= start; i--) {
            auto& e = event_log_[i];
            ImGui::TableNextRow();

            ImVec4 color = COL_WHITE;
            const char* type_str = "???";
            switch (e.type) {
            case HeapEvent::ALLOC:
                color = COL_GREEN;  type_str = "ALLOC"; break;
            case HeapEvent::FREE:
                color = COL_RED;    type_str = "FREE";  break;
            case HeapEvent::REALLOC:
                color = COL_YELLOW; type_str = "REALLOC"; break;
            }

            if (e.unbacked)
                color = COL_RED;

            ImGui::PushStyleColor(ImGuiCol_Text, color);

            ImGui::TableNextColumn();
            ImGui::Text("%s", type_str);

            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", (unsigned long long)e.address);

            ImGui::TableNextColumn();
            if (e.size > 0)
                ImGui::Text("%llu", (unsigned long long)e.size);
            else
                ImGui::TextDisabled("-");

            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", (unsigned long long)e.heap_handle);

            ImGui::TableNextColumn();
            if (e.unbacked)
                ImGui::TextColored(COL_RED, "!!");
            else
                ImGui::TextDisabled("-");

            ImGui::TableNextColumn();
            if (e.frame_count > 0)
                ImGui::Text("%u", e.frame_count);
            else
                ImGui::TextDisabled("-");

            ImGui::TableNextColumn();
            if (e.type == HeapEvent::FREE && e.lifetime_ms > 0) {
                if (e.lifetime_ms < 1.0)
                    ImGui::TextColored(COL_PURPLE, "<1ms");
                else if (e.lifetime_ms < 1000.0)
                    ImGui::Text("%.1fms", e.lifetime_ms);
                else
                    ImGui::Text("%.1fs", e.lifetime_ms / 1000.0);
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::PopStyleColor();
        }
        ImGui::EndTable();
    }
}

void App::RenderBlockDetail() {
    ImGui::Begin("Block Detail", nullptr,
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoCollapse);

    const auto& snap = GetDisplaySnapshot();
    if (selected_block_ < 0 ||
        selected_block_ >= (int)snap.blocks.size()) {
        ImGui::TextDisabled("Select a block to inspect.");
        ImGui::End();
        return;
    }

    auto& blk = snap.blocks[selected_block_];

    ImGui::Text("Address:"); ImGui::SameLine();
    ImGui::TextColored(COL_GREEN, "0x%llX", (unsigned long long)blk.address);

    ImGui::Text("Size:   "); ImGui::SameLine();
    ImGui::Text("%llu bytes (0x%llX)", (unsigned long long)blk.size,
                (unsigned long long)blk.size);

    ImGui::Text("Heap:   "); ImGui::SameLine();
    ImGui::Text("0x%llX", (unsigned long long)blk.heap_handle);

    ImGui::Separator();

    // === Entropy ===
    ImGui::Text("Entropy:"); ImGui::SameLine();
    ImGui::TextColored(EntropyColor(blk.entropy), "%.3f / 8.0", blk.entropy);
    ImGui::SameLine();
    if (blk.entropy < 3.5) ImGui::TextColored(COL_DIM, "(text/struct)");
    else if (blk.entropy < 6.0) ImGui::TextColored(COL_DIM, "(mixed)");
    else if (blk.entropy < 7.0) ImGui::TextColored(COL_DIM, "(compressed?)");
    else ImGui::TextColored(COL_RED, "(encrypted/shellcode!)");

    float bar_frac = (float)(blk.entropy / 8.0);
    ImVec4 bar_col = EntropyColor(blk.entropy);
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, bar_col);
    ImGui::ProgressBar(bar_frac, ImVec2(-1, 14));
    ImGui::PopStyleColor();

    // === Permissions ===
    ImGui::Text("Memory: "); ImGui::SameLine();
    if (blk.permissions & 0xF0)
        ImGui::TextColored(COL_RED, "%s  EXECUTABLE HEAP!", PermissionStr(blk.permissions));
    else
        ImGui::Text("%s", PermissionStr(blk.permissions));

    // === Classification ===
    ImGui::Text("Class:  ");
    uint32_t c = blk.classification;
    if (c == BLK_NONE) {
        ImGui::SameLine(); ImGui::TextDisabled("(none)");
    } else {
        if (c & BLK_PE_HEADER)     { ImGui::SameLine(); ImGui::TextColored(COL_RED, "[PE HEADER]"); }
        if (c & BLK_SHELLCODE)     { ImGui::SameLine(); ImGui::TextColored(COL_RED, "[SHELLCODE]"); }
        if (c & BLK_ENCRYPTED)     { ImGui::SameLine(); ImGui::TextColored(COL_ORANGE, "[ENCRYPTED]"); }
        if (c & BLK_EXECUTABLE)    { ImGui::SameLine(); ImGui::TextColored(COL_RED, "[EXEC MEM]"); }
        if (c & BLK_EMBEDDED_PE)   { ImGui::SameLine(); ImGui::TextColored(COL_RED, "[EMBEDDED PE]"); }
        if (c & BLK_HIGH_ENTROPY)  { ImGui::SameLine(); ImGui::TextColored(COL_ORANGE, "[HIGH ENTROPY]"); }
        if (c & BLK_INJECTED_PAGE) { ImGui::SameLine(); ImGui::TextColored(COL_YELLOW, "[PAGE ALIGN]"); }
        if (c & BLK_UNICODE_STR)   { ImGui::SameLine(); ImGui::TextColored(COL_CYAN, "[UNICODE]"); }
    }

    ImGui::Text("Hash:   "); ImGui::SameLine();
    ImGui::TextColored(COL_DIM, "%08X", blk.content_hash);

    ImGui::Separator();

    // === Hex Dump (multi-row, 16 bytes per row) ===
    if (ImGui::CollapsingHeader("Hex Dump", ImGuiTreeNodeFlags_DefaultOpen)) {
        int rows = (blk.preview_size + 15) / 16;
        for (int r = 0; r < rows; r++) {
            int offset = r * 16;
            int count = blk.preview_size - offset;
            if (count > 16) count = 16;

            char line[128];
            int pos = snprintf(line, sizeof(line), "%04X  ", offset);
            for (int j = 0; j < count; j++)
                pos += snprintf(line + pos, sizeof(line) - pos,
                                "%02X ", blk.preview[offset + j]);
            for (int j = count; j < 16; j++)
                pos += snprintf(line + pos, sizeof(line) - pos, "   ");
            pos += snprintf(line + pos, sizeof(line) - pos, " ");
            for (int j = 0; j < count; j++) {
                uint8_t ch = blk.preview[offset + j];
                line[pos++] = (ch >= 0x20 && ch < 0x7F) ? (char)ch : '.';
            }
            line[pos] = '\0';
            ImGui::TextColored(COL_DIM, "%s", line);
        }
    }

    // === Extracted Strings ===
    if (ImGui::CollapsingHeader("Strings", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto ascii = ExtractAsciiStrings(blk.preview, blk.preview_size);
        auto unicode = ExtractUnicodeStrings(blk.preview, blk.preview_size);
        auto iocs = ExtractIOCs(blk.preview, blk.preview_size);

        if (!iocs.empty()) {
            ImGui::TextColored(COL_RED, "IOC:");
            for (auto& s : iocs)
                ImGui::TextColored(COL_ORANGE, "    %s", s.c_str());
        }

        if (!ascii.empty()) {
            ImGui::TextColored(COL_DIM, "ASCII:");
            for (auto& s : ascii)
                ImGui::TextColored(COL_CYAN, "    \"%s\"", s.c_str());
        }

        if (!unicode.empty()) {
            ImGui::TextColored(COL_DIM, "Unicode:");
            for (auto& s : unicode)
                ImGui::TextColored(COL_PURPLE, "    L\"%s\"", s.c_str());
        }

        if (ascii.empty() && unicode.empty() && iocs.empty())
            ImGui::TextDisabled("No strings found");
    }

    // === Callstack (from alloc event cache) ===
    auto cs_it = callstack_cache_.find(blk.address);
    if (cs_it != callstack_cache_.end() && cs_it->second.frame_count > 0) {
        if (ImGui::CollapsingHeader("Callstack (alloc)",
                                     ImGuiTreeNodeFlags_DefaultOpen)) {
            auto& ci = cs_it->second;
            if (ci.unbacked) {
                ImGui::TextColored(COL_RED,
                    "!! UNBACKED CALLER DETECTED !!");
            }
            for (int i = 0; i < ci.frame_count; i++) {
                ImGui::TextColored(COL_DIM, "  [%d] 0x%llX",
                                   i, (unsigned long long)ci.frames[i]);
            }
        }
    }

    ImGui::End();
}

void App::RebuildStringCache() {
    cached_strings_.clear();
    const auto& snap = GetDisplaySnapshot();
    for (auto& blk : snap.blocks) {
        auto ascii = ExtractAsciiStrings(blk.preview, blk.preview_size);
        for (auto& s : ascii)
            cached_strings_.push_back({blk.address, 0, std::move(s)});

        auto unicode = ExtractUnicodeStrings(blk.preview, blk.preview_size);
        for (auto& s : unicode)
            cached_strings_.push_back({blk.address, 1, std::move(s)});

        auto iocs = ExtractIOCs(blk.preview, blk.preview_size);
        for (auto& s : iocs)
            cached_strings_.push_back({blk.address, 2, std::move(s)});
    }
}

void App::RenderAllStrings() {
    ImGui::InputText("Filter##strings", strings_filter_, sizeof(strings_filter_));
    ImGui::SameLine();
    ImGui::Text("(%zu strings)", cached_strings_.size());
    ImGui::Separator();

    if (ImGui::BeginTable("all_strings", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", 0, 130.0f);
        ImGui::TableSetupColumn("Type",    0, 60.0f);
        ImGui::TableSetupColumn("String",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (auto& es : cached_strings_) {
            if (strings_filter_[0]) {
                if (es.text.find(strings_filter_) == std::string::npos)
                    continue;
            }

            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", (unsigned long long)es.address);

            ImGui::TableNextColumn();
            switch (es.type) {
            case 0: ImGui::TextColored(COL_CYAN, "ASCII"); break;
            case 1: ImGui::TextColored(COL_PURPLE, "Unicode"); break;
            case 2: ImGui::TextColored(COL_ORANGE, "IOC"); break;
            }

            ImGui::TableNextColumn();
            ImVec4 col = (es.type == 0) ? COL_CYAN :
                         (es.type == 1) ? COL_PURPLE : COL_ORANGE;
            ImGui::TextColored(col, "%s", es.text.c_str());
        }
        ImGui::EndTable();
    }
}
