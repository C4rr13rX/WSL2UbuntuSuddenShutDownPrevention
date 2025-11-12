#pragma once

#include "event_collector.hpp"
#include "handle_utils.hpp"

namespace wslmon::windows {

class EventLogCollector : public EventCollector {
  public:
    EventLogCollector();
    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void poll_logs(ShutdownMonitorService &service);

    ScopedHandle stop_event_;
    ScopedHandle thread_handle_;
};

}  // namespace wslmon::windows

