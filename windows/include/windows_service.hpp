#pragma once

#include <Windows.h>

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "logger.hpp"
#include "ring_buffer.hpp"

namespace wslmon::windows {

class EventCollector;

class ShutdownMonitorService {
  public:
    ShutdownMonitorService();
    ~ShutdownMonitorService();

    void Run();
    void Stop();

    static ShutdownMonitorService &Instance();

    JsonLogger &Logger() { return logger_; }
    RingBuffer<EventRecord> &Buffer() { return buffer_; }

  private:
    void set_status(DWORD state, DWORD win32_exit_code = NO_ERROR, DWORD wait_hint_ms = 0);
    void run_collectors();

    SERVICE_STATUS_HANDLE status_handle_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread worker_;
    JsonLogger logger_;
    RingBuffer<EventRecord> buffer_;
    std::vector<std::unique_ptr<EventCollector>> collectors_;
};

void WINAPI ServiceMain(DWORD argc, LPWSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD control_code);

}  // namespace wslmon::windows

