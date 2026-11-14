#pragma once
#include <Windows.h>
#include "common/protocol.h"

struct QueuedEvent {
    uint32_t type;
    uint32_t size;
    uint8_t data[160];
};

class PipeClient {
public:
    void Init();
    void Cleanup();
    bool Connect();
    void Disconnect();
    bool Send(uint32_t type, const void* data, uint32_t data_size);
    bool Receive(MessageHeader& header, uint8_t* payload, uint32_t max_payload);
    bool IsConnected() const { return pipe_ != INVALID_HANDLE_VALUE; }

    bool QueueEvent(uint32_t type, const void* data, uint32_t size);
    int  FlushEvents();
    bool HasData();

private:
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    CRITICAL_SECTION cs_ = {};

    static const int RING_CAP = 4096;
    QueuedEvent ring_[RING_CAP];
    int ring_head_ = 0;
    int ring_tail_ = 0;
    CRITICAL_SECTION ring_cs_ = {};
};
