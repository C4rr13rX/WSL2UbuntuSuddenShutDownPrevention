#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wslmon {

struct EventAttribute {
    std::string key;
    std::string value;
};

struct EventRecord {
    std::string source;
    std::string category;
    std::string severity;
    std::string message;
    std::vector<EventAttribute> attributes;
    std::chrono::system_clock::time_point timestamp;
    std::uint64_t sequence;
};

std::string SerializeEvent(const EventRecord &record);
bool DeserializeEvent(std::string_view json, EventRecord &record);

}  // namespace wslmon

