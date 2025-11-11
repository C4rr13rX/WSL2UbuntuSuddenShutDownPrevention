#pragma once

#include "event_collector.hpp"

namespace wslmon::windows {

class PowerCollector : public EventCollector {
  public:
    PowerCollector();

    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void run(ShutdownMonitorService &service);

    HANDLE stop_event_ = nullptr;
    HANDLE thread_handle_ = nullptr;
};

}  // namespace wslmon::windows

