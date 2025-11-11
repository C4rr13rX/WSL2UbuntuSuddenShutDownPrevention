#pragma once

#include <Windows.h>

#include <map>
#include <string>
#include <vector>

#include "event_collector.hpp"

namespace wslmon::windows {

class ServiceHealthCollector : public EventCollector {
  public:
    ServiceHealthCollector();

    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void run(ShutdownMonitorService &service);
    void emit_status(ShutdownMonitorService &service, const std::wstring &service_name,
                     const SERVICE_STATUS_PROCESS &status, const SERVICE_STATUS_PROCESS *last_status);

    HANDLE stop_event_ = nullptr;
    HANDLE thread_handle_ = nullptr;
    std::vector<std::wstring> services_;
};

}  // namespace wslmon::windows
