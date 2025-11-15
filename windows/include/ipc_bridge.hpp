#pragma once

#include <Windows.h>
#include <winsock2.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "event.hpp"

namespace wslmon {
class JsonLogger;
class RingBufferBase;
}

namespace wslmon::windows {

class ShutdownMonitorService;

class IpcBridge {
  public:
    explicit IpcBridge(ShutdownMonitorService &service);
    ~IpcBridge();

    void Start();
    void Stop();

    void EnqueueHostEvent(const EventRecord &record);

  private:
    void pipe_worker();
    void unix_worker();

    bool load_secret();
    bool load_config();
    bool ensure_program_data();

    bool send_event_over_socket(const EventRecord &record);
    void handle_guest_event(EventRecord record);

    std::vector<std::uint8_t> secret_;
    std::vector<std::uint8_t> pipe_session_;
    std::vector<std::uint8_t> socket_session_;

    ShutdownMonitorService &service_;
    std::atomic<bool> running_{false};

    HANDLE pipe_handle_ = INVALID_HANDLE_VALUE;
    std::thread pipe_thread_;

    SOCKET socket_handle_ = INVALID_SOCKET;
    std::thread unix_thread_;

    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<EventRecord> outbound_;

    std::mutex socket_mutex_;

    std::string distro_name_;
    std::string socket_path_;
    std::wstring secret_path_;
    std::wstring config_path_;
};

}  // namespace wslmon::windows

