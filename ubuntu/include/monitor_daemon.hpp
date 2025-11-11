#pragma once

#include <atomic>
#include <thread>
#include <vector>

#include "logger.hpp"
#include "ring_buffer.hpp"

namespace wslmon::ubuntu {

class MonitorDaemon {
  public:
    MonitorDaemon();
    ~MonitorDaemon();

    void Run();
    void Stop();

  private:
    void watch_journal();
    void watch_resources();
    void watch_crashes();
    void emit(EventRecord record);

    std::atomic<bool> running_{false};
    std::vector<std::thread> workers_;
    JsonLogger logger_;
    RingBuffer<EventRecord> buffer_;
};

}  // namespace wslmon::ubuntu

