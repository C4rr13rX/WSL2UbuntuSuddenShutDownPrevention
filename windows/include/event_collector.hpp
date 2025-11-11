#pragma once

#include <Windows.h>

#include <string>

#include "event.hpp"

namespace wslmon::windows {

class ShutdownMonitorService;

class EventCollector {
  public:
    explicit EventCollector(std::wstring name);
    virtual ~EventCollector() = default;

    const std::wstring &Name() const { return name_; }

    virtual void Start(ShutdownMonitorService &service) = 0;
    virtual void Stop() = 0;

  protected:
    void emit(ShutdownMonitorService &service, EventRecord record);

  private:
    std::wstring name_;
};

}  // namespace wslmon::windows

