#include "pipe_client.h"

void PipeClient::Init() {
    InitializeCriticalSection(&cs_);
    InitializeCriticalSection(&ring_cs_);
}

void PipeClient::Cleanup() {
    Disconnect();
    DeleteCriticalSection(&cs_);
    DeleteCriticalSection(&ring_cs_);
}

bool PipeClient::Connect() {
    for (int i = 0; i < 50; i++) {
        pipe_ = CreateFileW(HEAPEX_PIPE_NAME,
                            GENERIC_READ | GENERIC_WRITE,
                            0, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe_ != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(pipe_, &mode, NULL, NULL);
            return true;
        }
        Sleep(100);
    }
    return false;
}

void PipeClient::Disconnect() {
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
}

bool PipeClient::Send(uint32_t type, const void* data, uint32_t data_size) {
    if (pipe_ == INVALID_HANDLE_VALUE) return false;

    uint8_t buf[sizeof(MessageHeader) + 2048];
    uint32_t total = sizeof(MessageHeader) + data_size;
    if (total > sizeof(buf)) return false;

    auto* hdr = reinterpret_cast<MessageHeader*>(buf);
    hdr->size = total;
    hdr->type = type;
    if (data_size > 0)
        memcpy(buf + sizeof(MessageHeader), data, data_size);

    EnterCriticalSection(&cs_);
    DWORD written;
    BOOL ok = WriteFile(pipe_, buf, total, &written, NULL);
    LeaveCriticalSection(&cs_);
    return ok && written == total;
}

bool PipeClient::Receive(MessageHeader& header, uint8_t* payload, uint32_t max_payload) {
    if (pipe_ == INVALID_HANDLE_VALUE) return false;

    DWORD read;
    if (!ReadFile(pipe_, &header, sizeof(header), &read, NULL) || read != sizeof(header))
        return false;

    uint32_t payload_size = header.size - sizeof(MessageHeader);
    if (payload_size > 0) {
        if (payload_size > max_payload) return false;
        if (!ReadFile(pipe_, payload, payload_size, &read, NULL) || read != payload_size)
            return false;
    }
    return true;
}

bool PipeClient::QueueEvent(uint32_t type, const void* data, uint32_t size) {
    if (!TryEnterCriticalSection(&ring_cs_)) return false;
    int next = (ring_head_ + 1) % RING_CAP;
    if (next == ring_tail_) {
        LeaveCriticalSection(&ring_cs_);
        return false;
    }
    ring_[ring_head_].type = type;
    uint32_t copy = (size < sizeof(ring_[0].data)) ? size : (uint32_t)sizeof(ring_[0].data);
    ring_[ring_head_].size = copy;
    memcpy(ring_[ring_head_].data, data, copy);
    ring_head_ = next;
    LeaveCriticalSection(&ring_cs_);
    return true;
}

int PipeClient::FlushEvents() {
    QueuedEvent batch[256];
    int count = 0;

    EnterCriticalSection(&ring_cs_);
    while (ring_tail_ != ring_head_ && count < 256) {
        batch[count++] = ring_[ring_tail_];
        ring_tail_ = (ring_tail_ + 1) % RING_CAP;
    }
    LeaveCriticalSection(&ring_cs_);

    for (int i = 0; i < count; i++)
        Send(batch[i].type, batch[i].data, batch[i].size);

    return count;
}

bool PipeClient::HasData() {
    if (pipe_ == INVALID_HANDLE_VALUE) return false;
    DWORD avail = 0;
    if (!PeekNamedPipe(pipe_, NULL, 0, NULL, &avail, NULL)) return false;
    return avail >= sizeof(MessageHeader);
}
