#pragma once

#include <Wbemidl.h>
#include <wrl/client.h>

#include "event_collector.hpp"
#include "handle_utils.hpp"

namespace wslmon::windows {

class SecurityCollector : public EventCollector {
  public:
    SecurityCollector();

    void Start(ShutdownMonitorService &service) override;
    void Stop() override;

  private:
    void run(ShutdownMonitorService &service);
    bool initialize_wmi();

    ScopedHandle stop_event_;
    ScopedHandle thread_handle_;
    Microsoft::WRL::ComPtr<IWbemServices> services_;
    Microsoft::WRL::ComPtr<IWbemLocator> locator_;
    bool com_initialized_ = false;
};

}  // namespace wslmon::windows

