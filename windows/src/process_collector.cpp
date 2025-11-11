#include "process_collector.hpp"

#include <TlHelp32.h>
#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <set>
#include <string>
#include <utility>

#include "windows_service.hpp"

namespace wslmon::windows {

namespace {
struct ProcessKey {
    std::wstring name;
    DWORD pid;
};

std::string wide_to_utf8(const std::wstring &input) {
    if (input.empty()) {
        return {};
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), result.data(), size_needed, nullptr, nullptr);
    return result;
}
}

ProcessCollector::ProcessCollector() : EventCollector(L"Process") {}

void ProcessCollector::Start(ShutdownMonitorService &service) {
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    auto *ctx = new std::pair<ProcessCollector *, ShutdownMonitorService *>(this, &service);
    thread_handle_ = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto *ctx = static_cast<std::pair<ProcessCollector *, ShutdownMonitorService *> *>(param);
        ctx->first->run(*ctx->second);
        delete ctx;
        return 0;
    }, ctx, 0, nullptr);
    if (!thread_handle_) {
        delete ctx;
        EventRecord record;
        record.category = "Process";
        record.severity = "Error";
        record.message = "Failed to create process collector thread";
        emit(service, std::move(record));
    }
}

void ProcessCollector::Stop() {
    if (stop_event_) {
        SetEvent(stop_event_);
    }
    if (thread_handle_) {
        WaitForSingleObject(thread_handle_, INFINITE);
        CloseHandle(thread_handle_);
        thread_handle_ = nullptr;
    }
    if (stop_event_) {
        CloseHandle(stop_event_);
        stop_event_ = nullptr;
    }
}

void ProcessCollector::run(ShutdownMonitorService &service) {
    std::set<DWORD> last_wsl_pids;

    while (WaitForSingleObject(stop_event_, 3000) == WAIT_TIMEOUT) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            EventRecord record;
            record.category = "Process";
            record.severity = "Warning";
            record.message = "CreateToolhelp32Snapshot failed";
            record.attributes.push_back({"error", std::to_string(GetLastError())});
            emit(service, std::move(record));
            continue;
        }
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        std::set<DWORD> current_wsl_pids;

        if (Process32FirstW(snapshot, &entry)) {
            do {
                std::wstring exe(entry.szExeFile);
                std::wstring lower = exe;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                if (lower == L"wsl.exe" || lower == L"vmmem" || lower == L"vmmemWSL.exe" || lower == L"vmwp.exe") {
                    current_wsl_pids.insert(entry.th32ProcessID);
                    if (!last_wsl_pids.count(entry.th32ProcessID)) {
                        EventRecord record;
                        record.category = "Process";
                        record.severity = "Info";
                        record.message = "Tracked process started";
                        record.attributes.push_back({"name", wide_to_utf8(exe)});
                        record.attributes.push_back({"pid", std::to_string(entry.th32ProcessID)});
                        record.attributes.push_back({"parent_pid", std::to_string(entry.th32ParentProcessID)});
                        emit(service, std::move(record));
                    }
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);

        for (DWORD pid : last_wsl_pids) {
            if (!current_wsl_pids.count(pid)) {
                EventRecord record;
                record.category = "Process";
                record.severity = "Warning";
                record.message = "Tracked process exited";
                record.attributes.push_back({"pid", std::to_string(pid)});
                emit(service, std::move(record));
            }
        }

        last_wsl_pids = std::move(current_wsl_pids);
    }
}

}  // namespace wslmon::windows

