#pragma once

class PipeClient;

namespace Hooks {
    bool Install(PipeClient* pipe);
    void Remove();
    bool IsInstalled();
}
