#include "pipe_server.h"
#include <algorithm>
#include <cstring>

bool PipeServer::Start() {
    pipe_ = CreateNamedPipeW(
        HEAPEX_PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 1024 * 1024, 1024 * 1024, 0, NULL);

    if (pipe_ == INVALID_HANDLE_VALUE) return false;

    running_ = true;
    thread_ = CreateThread(NULL, 0, ServerThread, this, 0, NULL);
    return thread_ != NULL;
}

void PipeServer::Stop() {
    running_ = false;
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CancelIoEx(pipe_, NULL);
        DisconnectNamedPipe(pipe_);
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
    if (thread_) {
        WaitForSingleObject(thread_, 3000);
        CloseHandle(thread_);
        thread_ = NULL;
    }
    connected_ = false;
}

void PipeServer::Restart() {
    Stop();
    Start();
}

bool PipeServer::IsRunning() const {
    if (!thread_) return false;
    DWORD code;
    if (GetExitCodeThread(thread_, &code))
        return code == STILL_ACTIVE;
    return false;
}

bool PipeServer::SendCommand(uint32_t type) {
    if (pipe_ == INVALID_HANDLE_VALUE || !connected_) return false;
    std::lock_guard<std::mutex> lock(mtx_);
    pending_cmds_.push(type);
    return true;
}

bool PipeServer::PopEvent(HeapEvent& evt) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (events_.empty()) return false;
    evt = events_.front();
    events_.pop();
    return true;
}

HeapSnapshot PipeServer::TakeSnapshot() {
    std::lock_guard<std::mutex> lock(mtx_);
    snapshot_ready_ = false;
    return std::move(ready_snapshot_);
}

DWORD WINAPI PipeServer::ServerThread(LPVOID param) {
    auto* self = static_cast<PipeServer*>(param);

    if (!ConnectNamedPipe(self->pipe_, NULL) &&
        GetLastError() != ERROR_PIPE_CONNECTED) {
        return 1;
    }
    self->connected_ = true;

    while (self->running_) {
        // Drain pending commands (GUI thread queues, we send)
        {
            std::queue<uint32_t> cmds;
            {
                std::lock_guard<std::mutex> lock(self->mtx_);
                std::swap(cmds, self->pending_cmds_);
            }
            while (!cmds.empty()) {
                MessageHeader cmd_hdr;
                cmd_hdr.size = sizeof(MessageHeader);
                cmd_hdr.type = cmds.front();
                cmds.pop();
                DWORD written;
                if (!WriteFile(self->pipe_, &cmd_hdr, sizeof(cmd_hdr), &written, NULL))
                    goto done;
            }
        }

        // Poll for incoming data (never block — avoids I/O serialization deadlock)
        DWORD avail = 0;
        if (!PeekNamedPipe(self->pipe_, NULL, 0, NULL, &avail, NULL))
            break;

        if (avail < sizeof(MessageHeader)) {
            Sleep(1);
            continue;
        }

        // Data ready — read the message
        MessageHeader hdr;
        DWORD bytesRead;
        if (!ReadFile(self->pipe_, &hdr, sizeof(hdr), &bytesRead, NULL) ||
            bytesRead != sizeof(hdr))
            break;

        uint32_t payload_size = hdr.size - sizeof(MessageHeader);
        std::vector<uint8_t> payload;
        if (payload_size > 0) {
            if (payload_size > 16 * 1024 * 1024) break;
            payload.resize(payload_size);
            if (!ReadFile(self->pipe_, payload.data(), payload_size,
                          &bytesRead, NULL) || bytesRead != payload_size)
                break;
        }

        self->ProcessMessage(hdr, payload.data());
    }
    done:

    self->connected_ = false;
    return 0;
}

void PipeServer::ProcessMessage(const MessageHeader& hdr, const uint8_t* payload) {
    std::lock_guard<std::mutex> lock(mtx_);

    switch (hdr.type) {
    case MSG_WORKER_READY: {
        auto* msg = reinterpret_cast<const WorkerReadyMsg*>(payload);
        worker_pid_ = msg->pid;
        break;
    }
    case MSG_SNAPSHOT_BEGIN:
        building_ = true;
        building_snapshot_ = {};
        QueryPerformanceCounter((LARGE_INTEGER*)&building_snapshot_.timestamp);
        break;

    case MSG_SNAPSHOT_BLOCK: {
        if (!building_) break;
        auto* msg = reinterpret_cast<const SnapshotBlockMsg*>(payload);
        HeapBlock blk = {};
        blk.heap_handle     = msg->heap_handle;
        blk.address         = msg->address;
        blk.size            = msg->size;
        blk.flags           = msg->flags;
        blk.entropy         = msg->entropy;
        blk.permissions     = msg->permissions;
        blk.content_hash    = msg->content_hash;
        blk.classification  = msg->classification;
        blk.preview_size    = msg->preview_size;
        memcpy(blk.preview, msg->preview, msg->preview_size);
        building_snapshot_.blocks.push_back(blk);

        bool found = false;
        for (auto& h : building_snapshot_.heaps) {
            if (h.handle == msg->heap_handle) {
                h.block_count++;
                h.total_size += msg->size;
                found = true;
                break;
            }
        }
        if (!found) {
            HeapInfo hi = {};
            hi.handle      = msg->heap_handle;
            hi.block_count = 1;
            hi.total_size  = msg->size;
            building_snapshot_.heaps.push_back(hi);
        }
        break;
    }
    case MSG_SNAPSHOT_END:
        building_ = false;
        ready_snapshot_ = std::move(building_snapshot_);
        snapshot_ready_ = true;
        break;

    case MSG_ALLOC_EVENT: {
        auto* msg = reinterpret_cast<const AllocEventMsg*>(payload);
        HeapEvent evt = {};
        evt.type        = HeapEvent::ALLOC;
        evt.heap_handle = msg->heap_handle;
        evt.address     = msg->address;
        evt.size        = msg->size;
        evt.old_address = 0;
        evt.timestamp   = msg->timestamp;
        evt.unbacked    = msg->unbacked != 0;
        evt.frame_count = msg->frame_count;
        for (int i = 0; i < msg->frame_count && i < MAX_STACK_FRAMES; i++)
            evt.frames[i] = msg->frames[i];
        events_.push(evt);
        if (events_.size() > 100000) events_.pop();
        break;
    }
    case MSG_FREE_EVENT: {
        auto* msg = reinterpret_cast<const FreeEventMsg*>(payload);
        HeapEvent evt = {};
        evt.type        = HeapEvent::FREE;
        evt.heap_handle = msg->heap_handle;
        evt.address     = msg->address;
        evt.size        = 0;
        evt.old_address = 0;
        evt.timestamp   = msg->timestamp;
        events_.push(evt);
        if (events_.size() > 100000) events_.pop();
        break;
    }
    case MSG_REALLOC_EVENT: {
        auto* msg = reinterpret_cast<const ReallocEventMsg*>(payload);
        HeapEvent evt = {};
        evt.type        = HeapEvent::REALLOC;
        evt.heap_handle = msg->heap_handle;
        evt.address     = msg->new_address;
        evt.size        = msg->new_size;
        evt.old_address = msg->old_address;
        evt.timestamp   = msg->timestamp;
        evt.unbacked    = msg->unbacked != 0;
        evt.frame_count = msg->frame_count;
        for (int i = 0; i < msg->frame_count && i < MAX_STACK_FRAMES; i++)
            evt.frames[i] = msg->frames[i];
        events_.push(evt);
        if (events_.size() > 100000) events_.pop();
        break;
    }
    }
}
