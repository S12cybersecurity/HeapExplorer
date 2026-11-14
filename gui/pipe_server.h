#pragma once
#include <Windows.h>
#include <vector>
#include <mutex>
#include <queue>
#include "common/protocol.h"
#include "common/heap_types.h"

class PipeServer {
public:
    bool Start();
    void Stop();
    void Restart();
    bool IsConnected() const { return connected_; }
    bool IsRunning() const;
    uint32_t WorkerPID() const { return worker_pid_; }

    bool SendCommand(uint32_t type);

    bool PopEvent(HeapEvent& evt);
    bool HasNewSnapshot() const { return snapshot_ready_; }
    HeapSnapshot TakeSnapshot();

private:
    static DWORD WINAPI ServerThread(LPVOID param);
    void ProcessMessage(const MessageHeader& hdr, const uint8_t* payload);

    HANDLE pipe_   = INVALID_HANDLE_VALUE;
    HANDLE thread_ = NULL;
    volatile bool running_   = false;
    volatile bool connected_ = false;

    std::mutex mtx_;
    std::queue<HeapEvent> events_;
    std::queue<uint32_t> pending_cmds_;
    HeapSnapshot building_snapshot_;
    HeapSnapshot ready_snapshot_;
    volatile bool snapshot_ready_ = false;
    bool building_ = false;

    uint32_t worker_pid_ = 0;
};
