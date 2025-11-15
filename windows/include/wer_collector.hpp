#pragma once

#include <Windows.h>

#include <string>
#include <unordered_map>
#include <vector>

#include "event_collector.hpp"
#include "handle_utils.hpp"

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

    ScopedHandle stop_event_;
    ScopedHandle thread_handle_;
    std::vector<std::wstring> directories_;
};

}  // namespace wslmon::windows
