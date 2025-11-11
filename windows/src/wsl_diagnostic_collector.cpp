#include "wsl_diagnostic_collector.hpp"

#include <cstdio>
#include <string>
#include <vector>

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

std::string read_pipe(FILE *pipe) {
    std::string output;
    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        output += buffer;
    }
    return output;
}

}  // namespace

WslDiagnosticCollector::WslDiagnosticCollector() : EventCollector(L"WslDiagnostics") {}

void WslDiagnosticCollector::Start(ShutdownMonitorService &service) {
    stop_event_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop_event_) {
        EventRecord record;
        record.category = "WslDiagnostics";
        record.severity = "Error";
        record.message = "Failed to create stop event for WSL diagnostics collector";
        emit(service, std::move(record));
        return;
    }

    auto ctx = std::make_unique<std::pair<WslDiagnosticCollector *, ShutdownMonitorService *>>(this, &service);
    HANDLE thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto *context = static_cast<std::pair<WslDiagnosticCollector *, ShutdownMonitorService *> *>(param);
        std::unique_ptr<std::pair<WslDiagnosticCollector *, ShutdownMonitorService *>> holder(context);
        holder->first->run(*holder->second);
        return 0;
    }, ctx.get(), 0, nullptr);
    if (!thread) {
        EventRecord record;
        record.category = "WslDiagnostics";
        record.severity = "Error";
        record.message = "Failed to create WSL diagnostics collector thread";
        emit(service, std::move(record));
        return;
    }
    thread_handle_.reset(thread);
    ctx.release();
}

void WslDiagnosticCollector::Stop() {
    if (stop_event_) {
        SetEvent(stop_event_.get());
    }
    if (thread_handle_) {
        WaitForSingleObject(thread_handle_.get(), INFINITE);
    }
    thread_handle_.reset();
    stop_event_.reset();
}

void WslDiagnosticCollector::collect_command(ShutdownMonitorService &service, const wchar_t *command,
                                             const char *category, const char *message) {
    FILE *pipe = _wpopen(command, L"rt");
    if (!pipe) {
        EventRecord record;
        record.category = category;
        record.severity = "Warning";
        record.message = std::string("Failed to execute command: ") + wide_to_utf8(std::wstring(command));
        record.attributes.push_back({"error", std::to_string(GetLastError())});
        emit(service, std::move(record));
        return;
    }
    std::string output = read_pipe(pipe);
    int exit_code = _pclose(pipe);
    EventRecord record;
    record.category = category;
    record.severity = exit_code == 0 ? "Info" : "Warning";
    record.message = message;
    record.attributes.push_back({"command", wide_to_utf8(std::wstring(command))});
    record.attributes.push_back({"exit_code", std::to_string(exit_code)});
    record.attributes.push_back({"output", output});
    emit(service, std::move(record));
}

void WslDiagnosticCollector::run(ShutdownMonitorService &service) {
    while (WaitForSingleObject(stop_event_.get(), 60000) == WAIT_TIMEOUT) {
        collect_command(service, L"wsl.exe --status 2>&1", "WslDiagnostics", "WSL status snapshot");
        collect_command(service, L"wsl.exe -l -v 2>&1", "WslDiagnostics", "WSL distributions");
    }
}

}  // namespace wslmon::windows
