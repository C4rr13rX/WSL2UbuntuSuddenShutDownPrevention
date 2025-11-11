#pragma once

#include <Windows.h>

#include "event_collector.hpp"

namespace wslmon::windows {

class WslDiagnosticCollector : public EventCollector {
  public:
    WslDiagnosticCollector();

    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void run(ShutdownMonitorService &service);
    void collect_command(ShutdownMonitorService &service, const wchar_t *command, const char *category,
                         const char *message);

    HANDLE stop_event_ = nullptr;
    HANDLE thread_handle_ = nullptr;
};

}  // namespace wslmon::windows
