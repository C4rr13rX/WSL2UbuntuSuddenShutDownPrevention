#pragma once

#include <Windows.h>

#include <string>
#include <unordered_map>
#include <vector>

#include "event_collector.hpp"

namespace wslmon::windows {

class WerCollector : public EventCollector {
  public:
    WerCollector();

    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void run(ShutdownMonitorService &service);
    void scan_directory(ShutdownMonitorService &service, const std::wstring &path, std::unordered_map<std::wstring, FILETIME> &state,
                        const char *category);

    HANDLE stop_event_ = nullptr;
    HANDLE thread_handle_ = nullptr;
    std::vector<std::wstring> directories_;
};

}  // namespace wslmon::windows
