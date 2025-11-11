#include "event_collector.hpp"

#include <chrono>

#include "windows_service.hpp"

namespace wslmon::windows {

EventCollector::EventCollector(std::wstring name) : name_(std::move(name)) {}

void EventCollector::emit(ShutdownMonitorService &service, EventRecord record) {
    record.source = std::string(name_.begin(), name_.end());
    record.timestamp = std::chrono::system_clock::now();
    service.Buffer().Push(record);
    service.Logger().Append(record);
}

}  // namespace wslmon::windows

