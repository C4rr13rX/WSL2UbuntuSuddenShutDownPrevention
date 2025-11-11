#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "logger.hpp"
#include "ring_buffer.hpp"
#include "ipc_bridge.hpp"

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
    void watch_kmsg();
    void watch_pressure();
    void watch_systemd_failures();
    void watch_network_health();
    void emit(EventRecord record);
    void add_common_attributes(EventRecord &record);
    void handle_peer_event(EventRecord record);

    std::atomic<bool> running_{false};
    std::vector<std::thread> workers_;
    JsonLogger logger_;
    RingBuffer<EventRecord> buffer_;
    std::string boot_id_;
    std::string machine_id_;
    std::string hostname_;
    std::unique_ptr<IpcBridge> bridge_;
};

}  // namespace wslmon::ubuntu

