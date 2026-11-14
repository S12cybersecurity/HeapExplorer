# HeapExplorer

Realtime heap analysis tool for Windows implant research and malware analysis.

## What it does

Injects a worker DLL into a target process and hooks `RtlAllocateHeap`, `RtlFreeHeap` and `RtlReAllocateHeap` via MinHook to capture every heap operation. Results stream to a GUI over a named pipe.

## Features

- **Heap browser**: all active blocks with address, size and 16-byte hex preview
- **Entropy detection**: flags encrypted/compressed buffers (>7.0)
- **String extraction**: finds C2 domains, pipe names, registry paths
- **Snapshot diff**: tracks New / Freed / Modified blocks between snapshots
- **Event timeline**: realtime alloc/free/realloc log with timestamps
- **VirtualQuery**: detects executable heap regions (RX anomaly)
- **Unbacked memory**: flags allocations originating from memory with no module on disk

## Usage

1. Open HeapExplorer
2. `File > Open File` to launch a target, or `Attach to Process` for a running one
3. DLL injects automatically and connects via named pipe
4. Take snapshots with `F5` or enable Auto Refresh

<img width="1842" height="950" alt="heapexplorer" src="https://github.com/user-attachments/assets/5c627eda-5539-4fde-8646-5d74f5fdf2da" />
