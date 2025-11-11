#include "wer_collector.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>
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

std::string filetime_to_string(const FILETIME &ft) {
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) {
        return {};
    }
    std::ostringstream oss;
    oss << st.wYear << '-' << std::setw(2) << std::setfill('0') << st.wMonth << '-' << std::setw(2) << st.wDay << 'T'
        << std::setw(2) << st.wHour << ':' << std::setw(2) << st.wMinute << ':' << std::setw(2) << st.wSecond;
    return oss.str();
}

}  // namespace

WerCollector::WerCollector() : EventCollector(L"WerWatcher") {
    directories_ = {L"C:/ProgramData/Microsoft/Windows/WER/ReportQueue", L"C:/ProgramData/Microsoft/Windows/WER/ReportArchive",
                    L"C:/Windows/LiveKernelReports"};
}

void WerCollector::Start(ShutdownMonitorService &service) {
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    auto *ctx = new std::pair<WerCollector *, ShutdownMonitorService *>(this, &service);
    thread_handle_ = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto *context = static_cast<std::pair<WerCollector *, ShutdownMonitorService *> *>(param);
        context->first->run(*context->second);
        delete context;
        return 0;
    }, ctx, 0, nullptr);
    if (!thread_handle_) {
        delete ctx;
        EventRecord record;
        record.category = "WER";
        record.severity = "Error";
        record.message = "Failed to create WER collector thread";
        emit(service, std::move(record));
    }
}

void WerCollector::Stop() {
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

void WerCollector::scan_directory(ShutdownMonitorService &service, const std::wstring &path,
                                  std::unordered_map<std::wstring, FILETIME> &state, const char *category) {
    WIN32_FIND_DATAW data{};
    std::wstring pattern = path;
    if (!pattern.empty() && pattern.back() != L'\\') {
        pattern += L'\\';
    }
    pattern += L"*";

    HANDLE handle = FindFirstFileW(pattern.c_str(), &data);
    if (handle == INVALID_HANDLE_VALUE) {
        EventRecord record;
        record.category = category;
        record.severity = "Warning";
        record.message = "Unable to enumerate directory";
        record.attributes.push_back({"path", wide_to_utf8(path)});
        record.attributes.push_back({"error", std::to_string(GetLastError())});
        emit(service, std::move(record));
        return;
    }

    do {
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        auto it = state.find(data.cFileName);
        if (it == state.end() || CompareFileTime(&it->second, &data.ftLastWriteTime) < 0) {
            EventRecord record;
            record.category = category;
            record.severity = "Info";
            record.message = "Crash artifact updated";
            record.attributes.push_back({"path", wide_to_utf8(path + L"\\" + data.cFileName)});
            record.attributes.push_back({"last_write", filetime_to_string(data.ftLastWriteTime)});
            emit(service, std::move(record));
            state[data.cFileName] = data.ftLastWriteTime;
        }
    } while (FindNextFileW(handle, &data));

    FindClose(handle);
}

void WerCollector::run(ShutdownMonitorService &service) {
    std::unordered_map<std::wstring, FILETIME> queue_state;
    std::unordered_map<std::wstring, FILETIME> archive_state;
    std::unordered_map<std::wstring, FILETIME> kernel_state;

    while (WaitForSingleObject(stop_event_, 15000) == WAIT_TIMEOUT) {
        scan_directory(service, directories_[0], queue_state, "WERQueue");
        scan_directory(service, directories_[1], archive_state, "WERArchive");
        scan_directory(service, directories_[2], kernel_state, "KernelDumps");
    }
}

}  // namespace wslmon::windows
