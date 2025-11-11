#include "process_collector.hpp"

#include <TlHelp32.h>
#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <cwctype>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <unordered_map>

#include "windows_service.hpp"

#pragma comment(lib, "Psapi.lib")

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
    stop_event_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop_event_) {
        EventRecord record;
        record.category = "Process";
        record.severity = "Error";
        record.message = "Failed to create stop event for process collector";
        emit(service, std::move(record));
        return;
    }

    auto ctx = std::make_unique<std::pair<ProcessCollector *, ShutdownMonitorService *>>(this, &service);
    HANDLE thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto *ctx_ptr = static_cast<std::pair<ProcessCollector *, ShutdownMonitorService *> *>(param);
        std::unique_ptr<std::pair<ProcessCollector *, ShutdownMonitorService *>> holder(ctx_ptr);
        holder->first->run(*holder->second);
        return 0;
    }, ctx.get(), 0, nullptr);
    if (!thread) {
        EventRecord record;
        record.category = "Process";
        record.severity = "Error";
        record.message = "Failed to create process collector thread";
        emit(service, std::move(record));
        return;
    }
    thread_handle_.reset(thread);
    ctx.release();
}

void ProcessCollector::Stop() {
    if (stop_event_) {
        SetEvent(stop_event_.get());
    }
    if (thread_handle_) {
        WaitForSingleObject(thread_handle_.get(), INFINITE);
    }
    thread_handle_.reset();
    stop_event_.reset();
}

void ProcessCollector::run(ShutdownMonitorService &service) {
    std::set<DWORD> last_wsl_pids;
    std::unordered_map<DWORD, std::uint64_t> last_working_sets;

    while (WaitForSingleObject(stop_event_.get(), 3000) == WAIT_TIMEOUT) {
        MEMORYSTATUSEX mem_status{};
        mem_status.dwLength = sizeof(mem_status);
        GlobalMemoryStatusEx(&mem_status);
        ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot || snapshot.get() == INVALID_HANDLE_VALUE) {
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

        if (Process32FirstW(snapshot.get(), &entry)) {
            do {
                std::wstring exe(entry.szExeFile);
                std::wstring lower = exe;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                if (lower == L"wsl.exe" || lower == L"vmmem" || lower == L"vmmemwsl.exe" || lower == L"vmwp.exe" ||
                    lower == L"wslhost.exe") {
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

                    ScopedHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE,
                                                     entry.th32ProcessID));
                    if (process) {
                        PROCESS_MEMORY_COUNTERS_EX counters{};
                        counters.cb = sizeof(counters);
                        if (GetProcessMemoryInfo(process.get(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&counters),
                                                 sizeof(counters))) {
                            double working_set_mb = counters.WorkingSetSize / (1024.0 * 1024.0);
                            double commit_mb = counters.PrivateUsage / (1024.0 * 1024.0);
                            double percent = mem_status.ullTotalPhys
                                                  ? (static_cast<double>(counters.WorkingSetSize) * 100.0 /
                                                     static_cast<double>(mem_status.ullTotalPhys))
                                                  : 0.0;
                            auto it = last_working_sets.find(entry.th32ProcessID);
                            bool significant_change = false;
                            if (it != last_working_sets.end()) {
                                double last_mb = static_cast<double>(it->second) / (1024.0 * 1024.0);
                                if (working_set_mb > last_mb * 1.25 || working_set_mb - last_mb > 256.0) {
                                    significant_change = true;
                                }
                            } else {
                                significant_change = true;
                            }
                            if (percent > 75.0 || significant_change) {
                                EventRecord usage;
                                usage.category = "Process";
                                usage.severity = percent > 90.0 ? "Critical" : "Warning";
                                usage.message = "Tracked process memory pressure";
                                usage.attributes.push_back({"name", wide_to_utf8(exe)});
                                usage.attributes.push_back({"pid", std::to_string(entry.th32ProcessID)});
                                usage.attributes.push_back({"working_set_mb", std::to_string(working_set_mb)});
                                usage.attributes.push_back({"commit_mb", std::to_string(commit_mb)});
                                usage.attributes.push_back({"working_set_percent", std::to_string(percent)});
                                emit(service, std::move(usage));
                            }
                            last_working_sets[entry.th32ProcessID] = counters.WorkingSetSize;
                        }
                    }
                }
            } while (Process32NextW(snapshot.get(), &entry));
        }

        for (DWORD pid : last_wsl_pids) {
            if (!current_wsl_pids.count(pid)) {
                last_working_sets.erase(pid);
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

