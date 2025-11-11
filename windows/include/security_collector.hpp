#pragma once

#include <Wbemidl.h>

#include "event_collector.hpp"

namespace wslmon::windows {

class SecurityCollector : public EventCollector {
  public:
    SecurityCollector();

    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void run(ShutdownMonitorService &service);
    bool initialize_wmi();
    void cleanup_wmi();

    HANDLE stop_event_ = nullptr;
    HANDLE thread_handle_ = nullptr;
    IWbemServices *services_ = nullptr;
    IWbemLocator *locator_ = nullptr;
    bool com_initialized_ = false;
};

}  // namespace wslmon::windows

