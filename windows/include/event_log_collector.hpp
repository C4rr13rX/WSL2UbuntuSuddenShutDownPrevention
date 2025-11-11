#pragma once

#include "event_collector.hpp"

namespace wslmon::windows {

class EventLogCollector : public EventCollector {
  public:
    EventLogCollector();
    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void poll_logs(ShutdownMonitorService &service);

    HANDLE stop_event_ = nullptr;
    HANDLE thread_handle_ = nullptr;
};

}  // namespace wslmon::windows

