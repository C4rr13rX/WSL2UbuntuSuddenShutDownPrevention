#pragma once

#include "event_collector.hpp"
#include "handle_utils.hpp"

namespace wslmon::windows {

class ProcessCollector : public EventCollector {
  public:
    ProcessCollector();

    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void run(ShutdownMonitorService &service);

    ScopedHandle stop_event_;
    ScopedHandle thread_handle_;
};

}  // namespace wslmon::windows

