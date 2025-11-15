#pragma once

#include <Windows.h>

#include "event_collector.hpp"
#include "handle_utils.hpp"

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

    ScopedHandle stop_event_;
    ScopedHandle thread_handle_;
};

}  // namespace wslmon::windows
