#include "power_collector.hpp"

#include <PowrProf.h>
#include <Windows.h>

#include <cstring>
#include <memory>
#include <string>
#include <utility>

#include "windows_service.hpp"

#pragma comment(lib, "PowrProf.lib")

namespace wslmon::windows {

namespace {
std::string wide_to_utf8(const std::wstring &input) {
    if (input.empty()) {
        return {};
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), result.data(), size_needed, nullptr, nullptr);
    return result;
}

std::string ac_state_to_string(BYTE state) {
    switch (state) {
        case 0:
            return "Offline";
        case 1:
            return "Online";
        case 255:
            return "Unknown";
        default:
            return std::to_string(state);
    }
}

std::string battery_flag_to_string(BYTE flag) {
    if (flag == 128) {
        return "NoBattery";
    }
    std::string result;
    if (flag & 1) result += "High|";
    if (flag & 2) result += "Low|";
    if (flag & 4) result += "Critical|";
    if (flag & 8) result += "Charging|";
    if (flag & 64) result += "Unknown|";
    if (!result.empty() && result.back() == '|') {
        result.pop_back();
    }
    return result;
}
}

PowerCollector::PowerCollector() : EventCollector(L"Power") {}

void PowerCollector::Start(ShutdownMonitorService &service) {
    stop_event_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop_event_) {
        EventRecord record;
        record.category = "Power";
        record.severity = "Error";
        record.message = "Failed to create stop event for power collector";
        emit(service, std::move(record));
        return;
    }

    auto ctx = std::make_unique<std::pair<PowerCollector *, ShutdownMonitorService *>>(this, &service);
    HANDLE thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto *ctx_ptr = static_cast<std::pair<PowerCollector *, ShutdownMonitorService *> *>(param);
        std::unique_ptr<std::pair<PowerCollector *, ShutdownMonitorService *>> holder(ctx_ptr);
        holder->first->run(*holder->second);
        return 0;
    }, ctx.get(), 0, nullptr);
    if (!thread) {
        EventRecord record;
        record.category = "Power";
        record.severity = "Error";
        record.message = "Failed to create power collector thread";
        emit(service, std::move(record));
        return;
    }
    thread_handle_.reset(thread);
    ctx.release();
}

void PowerCollector::Stop() {
    if (stop_event_) {
        SetEvent(stop_event_.get());
    }
    if (thread_handle_) {
        WaitForSingleObject(thread_handle_.get(), INFINITE);
    }
    thread_handle_.reset();
    stop_event_.reset();
}

void PowerCollector::run(ShutdownMonitorService &service) {
    SYSTEM_POWER_STATUS status{};
    SYSTEM_POWER_STATUS last_status{};
    ZeroMemory(&last_status, sizeof(last_status));
    bool first = true;

    while (WaitForSingleObject(stop_event_.get(), 5000) == WAIT_TIMEOUT) {
        if (!GetSystemPowerStatus(&status)) {
            EventRecord record;
            record.category = "Power";
            record.severity = "Warning";
            record.message = "GetSystemPowerStatus failed";
            record.attributes.push_back({"error", std::to_string(GetLastError())});
            emit(service, std::move(record));
            continue;
        }
        if (first || memcmp(&status, &last_status, sizeof(status)) != 0) {
            EventRecord record;
            record.category = "Power";
            record.severity = "Info";
            record.message = "Power status changed";
            record.attributes.push_back({"ACLineStatus", ac_state_to_string(status.ACLineStatus)});
            record.attributes.push_back({"BatteryFlag", battery_flag_to_string(status.BatteryFlag)});
            record.attributes.push_back({"BatteryLifePercent", std::to_string(status.BatteryLifePercent)});
            record.attributes.push_back({"BatteryLifeTime", std::to_string(status.BatteryLifeTime)});
            record.attributes.push_back({"BatteryFullLifeTime", std::to_string(status.BatteryFullLifeTime)});
            emit(service, std::move(record));

            GUID *scheme = nullptr;
            if (PowerGetActiveScheme(nullptr, &scheme) == ERROR_SUCCESS && scheme) {
                LPOLESTR guid_string = nullptr;
                if (StringFromCLSID(*scheme, &guid_string) == S_OK && guid_string) {
                    EventRecord scheme_record;
                    scheme_record.category = "Power";
                    scheme_record.severity = "Info";
                    scheme_record.message = "Active power scheme";
                    scheme_record.attributes.push_back({"Guid", wide_to_utf8(guid_string)});
                    emit(service, std::move(scheme_record));
                    CoTaskMemFree(guid_string);
                }
                LocalFree(scheme);
            }
            last_status = status;
            first = false;
        }
    }
}

}  // namespace wslmon::windows

