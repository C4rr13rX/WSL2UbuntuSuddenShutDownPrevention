#include "service_health_collector.hpp"

#include <chrono>
#include <string>
#include <unordered_map>

#include "windows_service.hpp"

namespace wslmon::windows {

namespace {
std::string wide_to_utf8(const std::wstring &value) {
    if (value.empty()) {
        return {};
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), size, nullptr, nullptr);
    return out;
}

std::string state_to_string(DWORD state) {
    switch (state) {
        case SERVICE_STOPPED:
            return "Stopped";
        case SERVICE_START_PENDING:
            return "StartPending";
        case SERVICE_STOP_PENDING:
            return "StopPending";
        case SERVICE_RUNNING:
            return "Running";
        case SERVICE_CONTINUE_PENDING:
            return "ContinuePending";
        case SERVICE_PAUSE_PENDING:
            return "PausePending";
        case SERVICE_PAUSED:
            return "Paused";
        default:
            return std::to_string(state);
    }
}

}  // namespace

ServiceHealthCollector::ServiceHealthCollector() : EventCollector(L"ServiceHealth") {
    services_ = {L"LxssManager", L"LxssManagerUser", L"vmcompute", L"vmms"};
}

void ServiceHealthCollector::Start(ShutdownMonitorService &service) {
    stop_event_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop_event_) {
        EventRecord record;
        record.category = "ServiceHealth";
        record.severity = "Error";
        record.message = "Failed to create stop event for service health collector";
        emit(service, std::move(record));
        return;
    }

    auto ctx = std::make_unique<std::pair<ServiceHealthCollector *, ShutdownMonitorService *>>(this, &service);
    HANDLE thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto *context = static_cast<std::pair<ServiceHealthCollector *, ShutdownMonitorService *> *>(param);
        std::unique_ptr<std::pair<ServiceHealthCollector *, ShutdownMonitorService *>> holder(context);
        holder->first->run(*holder->second);
        return 0;
    }, ctx.get(), 0, nullptr);
    if (!thread) {
        EventRecord record;
        record.category = "ServiceHealth";
        record.severity = "Error";
        record.message = "Failed to create service health collector thread";
        emit(service, std::move(record));
        return;
    }
    thread_handle_.reset(thread);
    ctx.release();
}

void ServiceHealthCollector::Stop() {
    if (stop_event_) {
        SetEvent(stop_event_.get());
    }
    if (thread_handle_) {
        WaitForSingleObject(thread_handle_.get(), INFINITE);
    }
    thread_handle_.reset();
    stop_event_.reset();
}

void ServiceHealthCollector::emit_status(ShutdownMonitorService &service, const std::wstring &service_name,
                                         const SERVICE_STATUS_PROCESS &status,
                                         const SERVICE_STATUS_PROCESS *last_status) {
    EventRecord record;
    record.category = "ServiceHealth";
    record.message = "Service state";
    record.attributes.push_back({"service", wide_to_utf8(service_name)});
    record.attributes.push_back({"state", state_to_string(status.dwCurrentState)});
    record.attributes.push_back({"pid", std::to_string(status.dwProcessId)});
    if (status.dwWin32ExitCode != 0) {
        record.attributes.push_back({"exit_code", std::to_string(status.dwWin32ExitCode)});
    }
    if (status.dwServiceSpecificExitCode != 0) {
        record.attributes.push_back({"service_exit_code", std::to_string(status.dwServiceSpecificExitCode)});
    }
    if (last_status) {
        record.attributes.push_back({"previous_state", state_to_string(last_status->dwCurrentState)});
        if (last_status->dwProcessId != status.dwProcessId) {
            record.severity = "Warning";
            record.attributes.push_back({"previous_pid", std::to_string(last_status->dwProcessId)});
            record.message = "Service process changed";
        }
    }
    emit(service, std::move(record));
}

void ServiceHealthCollector::run(ShutdownMonitorService &service) {
    ScopedServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        EventRecord record;
        record.category = "ServiceHealth";
        record.severity = "Error";
        record.message = "Failed to open service control manager";
        record.attributes.push_back({"error", std::to_string(GetLastError())});
        emit(service, std::move(record));
        return;
    }

    std::unordered_map<std::wstring, SERVICE_STATUS_PROCESS> last_states;

    while (WaitForSingleObject(stop_event_.get(), 5000) == WAIT_TIMEOUT) {
        for (const auto &service_name : services_) {
            ScopedServiceHandle svc(OpenServiceW(scm.get(), service_name.c_str(), SERVICE_QUERY_STATUS));
            if (!svc) {
                EventRecord record;
                record.category = "ServiceHealth";
                record.severity = "Warning";
                record.message = "Unable to open service";
                record.attributes.push_back({"service", wide_to_utf8(service_name)});
                record.attributes.push_back({"error", std::to_string(GetLastError())});
                emit(service, std::move(record));
                continue;
            }

            SERVICE_STATUS_PROCESS status{};
            DWORD bytes_needed = 0;
            if (!QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                                      &bytes_needed)) {
                EventRecord record;
                record.category = "ServiceHealth";
                record.severity = "Warning";
                record.message = "QueryServiceStatusEx failed";
                record.attributes.push_back({"service", wide_to_utf8(service_name)});
                record.attributes.push_back({"error", std::to_string(GetLastError())});
                emit(service, std::move(record));
                continue;
            }

            auto it = last_states.find(service_name);
            if (it == last_states.end() || it->second.dwCurrentState != status.dwCurrentState ||
                it->second.dwProcessId != status.dwProcessId ||
                it->second.dwWin32ExitCode != status.dwWin32ExitCode) {
                const SERVICE_STATUS_PROCESS *last_ptr = it == last_states.end() ? nullptr : &it->second;
                emit_status(service, service_name, status, last_ptr);
                last_states[service_name] = status;
            }
        }
    }
}

}  // namespace wslmon::windows
