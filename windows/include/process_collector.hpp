#pragma once

#include "event_collector.hpp"

namespace wslmon::windows {

class ProcessCollector : public EventCollector {
  public:
    ProcessCollector();

    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void run(ShutdownMonitorService &service);

    HANDLE stop_event_ = nullptr;
    HANDLE thread_handle_ = nullptr;
};

}  // namespace wslmon::windows

