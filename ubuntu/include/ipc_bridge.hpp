#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "event.hpp"

namespace wslmon::ubuntu {

class IpcBridge {
  public:
    using EventCallback = std::function<void(EventRecord)>;

    IpcBridge(EventCallback callback, std::string log_origin);
    ~IpcBridge();

    void Start();
    void Stop();

    void EnqueueGuestEvent(const EventRecord &record);

  private:
    void pipe_worker();
    void unix_worker();

    bool load_secret();
    bool connect_named_pipe(int &fd);
    bool send_event_via_pipe(int fd, const EventRecord &record, const std::vector<std::uint8_t> &session);

    EventCallback callback_;
    std::string log_origin_;

    std::atomic<bool> running_{false};

    std::thread pipe_thread_;
    std::thread unix_thread_;

    int pipe_fd_ = -1;
    int server_fd_ = -1;

    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<EventRecord> outbound_;

    std::vector<std::uint8_t> secret_;
    std::string secret_path_;

    std::mutex session_mutex_;
    std::vector<std::uint8_t> pipe_session_;

    static constexpr const char *kPipePath = "//./pipe/WslMonitorBridge";
    static constexpr const char *kUnixSocketPath = "/var/run/wsl-monitor/host.sock";
    static constexpr const char *kSecretInstallPath = "/etc/wsl-monitor/ipc.key";
};

}  // namespace wslmon::ubuntu

