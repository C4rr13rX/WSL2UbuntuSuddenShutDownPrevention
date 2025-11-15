#include "event_log_collector.hpp"

#include <Evntcons.h>
#include <wevtapi.h>
#include <winmeta.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "windows_service.hpp"

#pragma comment(lib, "wevtapi.lib")

namespace wslmon::windows {

namespace {
struct ChannelState {
    std::wstring name;
    std::wstring display_name;
    std::uint64_t last_record_id = 0;
};

std::wstring render_xml(EVT_HANDLE event) {
    DWORD buffer_used = 0;
    DWORD property_count = 0;
    if (!EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &buffer_used, &property_count)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return L"";
        }
    }
    std::wstring xml;
    xml.resize(buffer_used / sizeof(wchar_t));
    if (!EvtRender(nullptr, event, EvtRenderEventXml, buffer_used, xml.data(), &buffer_used, &property_count)) {
        return L"";
    }
    if (!xml.empty() && xml.back() == L'\0') {
        xml.pop_back();
    }
    return xml;
}

std::uint64_t get_record_id(EVT_HANDLE event) {
    DWORD buffer_used = 0;
    EVT_VARIANT value{};
    if (!EvtGetEventInfo(event, EventRecordId, sizeof(value), &value, &buffer_used)) {
        return 0;
    }
    return value.UInt64Val;
}

std::string wide_to_utf8(const std::wstring &input) {
    if (input.empty()) {
        return {};
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), result.data(), size_needed, nullptr, nullptr);
    return result;
}

std::uint32_t get_event_id(EVT_HANDLE event) {
    DWORD buffer_used = 0;
    EVT_VARIANT value{};
    if (!EvtGetEventInfo(event, EventId, sizeof(value), &value, &buffer_used)) {
        return 0;
    }
    return value.UInt16Val;
}

std::uint8_t get_level(EVT_HANDLE event) {
    DWORD buffer_used = 0;
    EVT_VARIANT values[EvtSystemPropertyIdEND]{};
    if (!EvtRender(nullptr, event, EvtRenderEventValues, sizeof(values), values, &buffer_used, nullptr)) {
        return 0;
    }
    return values[EvtSystemLevel].ByteVal;
}

std::string level_to_severity(std::uint8_t level) {
    switch (level) {
        case WINEVENT_LEVEL_CRITICAL:
            return "Critical";
        case WINEVENT_LEVEL_ERROR:
            return "Error";
        case WINEVENT_LEVEL_WARNING:
            return "Warning";
        case WINEVENT_LEVEL_VERBOSE:
            return "Verbose";
        case WINEVENT_LEVEL_LOG_ALWAYS:
        case WINEVENT_LEVEL_INFO:
        default:
            return "Info";
    }
}

void enrich_attributes(EventRecord &record, const ChannelState &channel, EVT_HANDLE event, std::uint64_t record_id) {
    record.attributes.push_back({"channel", wide_to_utf8(channel.name)});
    if (!channel.display_name.empty()) {
        record.attributes.push_back({"channel_display", wide_to_utf8(channel.display_name)});
    }
    record.attributes.push_back({"record_id", std::to_string(record_id)});
    const auto event_id = get_event_id(event);
    if (event_id != 0) {
        record.attributes.push_back({"event_id", std::to_string(event_id)});
    }
    const auto level = get_level(event);
    record.attributes.push_back({"level", std::to_string(level)});
    record.severity = level_to_severity(level);
}
}

EventLogCollector::EventLogCollector() : EventCollector(L"EventLog") {}

void EventLogCollector::Start(ShutdownMonitorService &service) {
    stop_event_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop_event_) {
        EventRecord record;
        record.category = "EventLog";
        record.severity = "Error";
        record.message = "Failed to create stop event for event log collector";
        service.Logger().Append(record);
        return;
    }

    auto ctx = std::make_unique<std::pair<EventLogCollector *, ShutdownMonitorService *>>(this, &service);
    HANDLE thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto *ctx_ptr =
            static_cast<std::pair<EventLogCollector *, ShutdownMonitorService *> *>(param);
        std::unique_ptr<std::pair<EventLogCollector *, ShutdownMonitorService *>> ctx_holder(ctx_ptr);
        ctx_holder->first->poll_logs(*ctx_holder->second);
        return 0;
    }, ctx.get(), 0, nullptr);
    if (!thread) {
        EventRecord record;
        record.category = "EventLog";
        record.severity = "Error";
        record.message = "Failed to create event log collector thread";
        service.Logger().Append(record);
        return;
    }
    thread_handle_.reset(thread);
    ctx.release();
}

void EventLogCollector::Stop() {
    if (stop_event_) {
        SetEvent(stop_event_.get());
    }
    if (thread_handle_) {
        WaitForSingleObject(thread_handle_.get(), INFINITE);
    }
    thread_handle_.reset();
    stop_event_.reset();
}

void EventLogCollector::poll_logs(ShutdownMonitorService &service) {
    std::vector<ChannelState> channels = {
        {L"System", L"Windows System"},
        {L"Application", L"Windows Application"},
        {L"Microsoft-Windows-Hyper-V-Worker-Admin", L"Hyper-V Worker"},
        {L"Microsoft-Windows-Hyper-V-Compute-Admin", L"Hyper-V Compute"},
        {L"Microsoft-Windows-Hyper-V-VmSwitch-Operational", L"Hyper-V vSwitch"},
        {L"Microsoft-Windows-Lxss/Operational", L"WSL Runtime"},
        {L"Microsoft-Windows-Lxss-Client/Operational", L"WSL Client"},
        {L"Microsoft-Windows-Subsys-Linux/Operational", L"WSL Subsystem"},
        {L"Microsoft-Windows-Winlogon/Operational", L"Winlogon"},
        {L"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", L"Firewall"},
        {L"Microsoft-Windows-Windows Defender/Operational", L"Defender"},
        {L"Microsoft-Windows-WER-SystemErrorReporting/Operational", L"WER System"}};

    while (WaitForSingleObject(stop_event_.get(), 1000) == WAIT_TIMEOUT) {
        for (auto &channel : channels) {
            ScopedEvtHandle query(EvtQuery(nullptr, channel.name.c_str(), L"*",
                                           EvtQueryChannelPath | EvtQueryReverseDirection));
            if (!query) {
                continue;
            }
            EVT_HANDLE events[16];
            DWORD returned = 0;
            while (EvtNext(query.get(), 16, events, 0, 0, &returned)) {
                for (DWORD i = 0; i < returned; ++i) {
                    std::uint64_t record_id = get_record_id(events[i]);
                    if (record_id == 0 || record_id <= channel.last_record_id) {
                        EvtClose(events[i]);
                        continue;
                    }
                    channel.last_record_id = record_id;
                    EventRecord record;
                    record.category = "EventLog";
                    record.message = wide_to_utf8(render_xml(events[i]));
                    record.sequence = record_id;
                    enrich_attributes(record, channel, events[i], record_id);
                    emit(service, std::move(record));
                    EvtClose(events[i]);
                }
            }
        }
    }
}

}  // namespace wslmon::windows

