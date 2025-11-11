#include "windows_service.hpp"

#include <Windows.h>
#include <Wtsapi32.h>

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <thread>

#include "event_collector.hpp"
#include "event_log_collector.hpp"
#include "power_collector.hpp"
#include "process_collector.hpp"
#include "security_collector.hpp"

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")

namespace wslmon::windows {

namespace {
constexpr wchar_t kServiceName[] = L"WslShutdownMonitor";
}

ShutdownMonitorService::ShutdownMonitorService()
    : logger_(std::filesystem::path{L"C:/ProgramData/WslMonitor/host-events.log"}),
      buffer_(1024) {}

ShutdownMonitorService::~ShutdownMonitorService() { Stop(); }

ShutdownMonitorService &ShutdownMonitorService::Instance() {
    static ShutdownMonitorService instance;
    return instance;
}

void ShutdownMonitorService::Run() {
    running_.store(true);
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT;
    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 2000;

    status_handle_ = RegisterServiceCtrlHandlerW(kServiceName, ServiceCtrlHandler);
    if (!status_handle_) {
        throw std::runtime_error("Failed to register service control handler");
    }

    set_status(SERVICE_START_PENDING, NO_ERROR, 4000);

    collectors_.emplace_back(std::make_unique<EventLogCollector>());
    collectors_.emplace_back(std::make_unique<PowerCollector>());
    collectors_.emplace_back(std::make_unique<ProcessCollector>());
    collectors_.emplace_back(std::make_unique<SecurityCollector>());

    worker_ = std::thread(&ShutdownMonitorService::run_collectors, this);

    set_status(SERVICE_RUNNING);
}

void ShutdownMonitorService::Stop() {
    if (!running_.exchange(false)) {
        return;
    }
    for (auto &collector : collectors_) {
        collector->Stop();
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    set_status(SERVICE_STOPPED);
}

void ShutdownMonitorService::set_status(DWORD state, DWORD win32_exit_code, DWORD wait_hint_ms) {
    if (!status_handle_) {
        return;
    }
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT;
    status.dwWin32ExitCode = win32_exit_code;
    status.dwWaitHint = wait_hint_ms;

    SetServiceStatus(status_handle_, &status);
}

void ShutdownMonitorService::run_collectors() {
    for (auto &collector : collectors_) {
        collector->Start(*this);
    }
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR * /*argv*/) {
    ShutdownMonitorService &service = ShutdownMonitorService::Instance();
    try {
        service.Run();
    } catch (const std::exception &ex) {
        EventRecord record;
        record.category = "Service";
        record.severity = "Critical";
        record.message = std::string("Failed to start service: ") + ex.what();
        service.Logger().Append(record);
    }
}

void WINAPI ServiceCtrlHandler(DWORD control_code) {
    ShutdownMonitorService &service = ShutdownMonitorService::Instance();
    switch (control_code) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            service.Stop();
            break;
        case SERVICE_CONTROL_POWEREVENT: {
            EventRecord record;
            record.category = "PowerEvent";
            record.severity = "Info";
            record.message = "Received power event";
            record.attributes.push_back({"code", std::to_string(control_code)});
            service.Logger().Append(record);
            break;
        }
        default:
            break;
    }
}

}  // namespace wslmon::windows

