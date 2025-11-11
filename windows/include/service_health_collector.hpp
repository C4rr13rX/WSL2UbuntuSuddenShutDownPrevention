#pragma once

#include <Windows.h>

#include <map>
#include <string>
#include <vector>

#include "event_collector.hpp"
#include "handle_utils.hpp"

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

    ScopedHandle stop_event_;
    ScopedHandle thread_handle_;
    std::vector<std::wstring> services_;
};

}  // namespace wslmon::windows
