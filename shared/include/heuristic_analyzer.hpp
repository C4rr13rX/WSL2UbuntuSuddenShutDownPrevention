#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "event.hpp"

namespace wslmon {

struct TimelineEvent {
    std::string origin;
    EventRecord record;
    std::string chain_hash;
};

struct HeuristicSupportingEvent {
    std::string origin;
    EventRecord record;
};

struct HeuristicInsight {
    std::string id;
    std::string summary;
    std::string rationale;
    std::string confidence;
    std::vector<HeuristicSupportingEvent> supporting_events;
};

struct ChannelHealthMetrics {
    std::size_t info = 0;
    std::size_t warning = 0;
    std::size_t error = 0;
    std::size_t critical = 0;
    std::size_t total = 0;
    std::chrono::system_clock::time_point first_timestamp{};
    std::chrono::system_clock::time_point last_timestamp{};
};

struct CrossChannelHealthSnapshot {
    ChannelHealthMetrics host;
    ChannelHealthMetrics guest;
};

std::vector<HeuristicInsight> AnalyzeEventTimeline(const std::vector<TimelineEvent> &events);
CrossChannelHealthSnapshot ComputeCrossChannelSnapshot(const std::vector<TimelineEvent> &events);

}  // namespace wslmon

