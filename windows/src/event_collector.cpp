#include "event_collector.hpp"

#include <algorithm>
#include <chrono>
#include <winreg.h>

#include "windows_service.hpp"

namespace wslmon::windows {

namespace {
std::string WideToUtf8(const std::wstring &input) {
    if (input.empty()) {
        return {};
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string output(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), output.data(), size, nullptr, nullptr);
    return output;
}

std::string ResolveHostname() {
    DWORD size = 0;
    GetComputerNameExW(ComputerNameDnsHostname, nullptr, &size);
    if (size == 0) {
        return {};
    }
    std::wstring buffer(size, L'\0');
    if (!GetComputerNameExW(ComputerNameDnsHostname, buffer.data(), &size)) {
        return {};
    }
    buffer.resize(size);
    return WideToUtf8(buffer);
}

std::string ResolveMachineGuid() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return {};
    }
    wchar_t value[256] = {0};
    DWORD size = sizeof(value);
    LONG status = RegGetValueW(key, nullptr, L"MachineGuid", RRF_RT_REG_SZ, nullptr, value, &size);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) {
        return {};
    }
    return WideToUtf8(value);
}

const std::string &Hostname() {
    static const std::string hostname = ResolveHostname();
    return hostname;
}

const std::string &MachineGuid() {
    static const std::string guid = ResolveMachineGuid();
    return guid;
}

}  // namespace

EventCollector::EventCollector(std::wstring name) : name_(std::move(name)) {}

void EventCollector::emit(ShutdownMonitorService &service, EventRecord record) {
    record.source = std::string(name_.begin(), name_.end());
    record.timestamp = std::chrono::system_clock::now();
    auto ensure_attr = [&record](const std::string &key, const std::string &value) {
        if (value.empty()) {
            return;
        }
        auto it = std::find_if(record.attributes.begin(), record.attributes.end(),
                               [&key](const auto &attr) { return attr.key == key; });
        if (it == record.attributes.end()) {
            record.attributes.push_back({key, value});
        }
    };
    ensure_attr("hostname", Hostname());
    ensure_attr("machine_guid", MachineGuid());
    service.Buffer().Push(record);
    service.Logger().Append(record);
}

}  // namespace wslmon::windows

