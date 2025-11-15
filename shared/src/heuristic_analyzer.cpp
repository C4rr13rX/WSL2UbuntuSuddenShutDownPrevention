#include "heuristic_analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <string_view>

namespace wslmon {
namespace {
std::optional<std::string> find_attribute(const EventRecord &record, std::string_view key) {
    for (const auto &attr : record.attributes) {
        if (attr.key == key) {
            return attr.value;
        }
    }
    return std::nullopt;
}

bool contains_case_insensitive(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) ==
                                                    std::tolower(static_cast<unsigned char>(b)); });
    return it != haystack.end();
}

bool is_recent(const EventRecord &reference, const EventRecord &candidate,
               std::chrono::minutes window = std::chrono::minutes(10)) {
    if (candidate.timestamp == std::chrono::system_clock::time_point{}) {
        return false;
    }
    if (reference.timestamp == std::chrono::system_clock::time_point{}) {
        return true;
    }
    auto delta = reference.timestamp - candidate.timestamp;
    return delta >= std::chrono::minutes(0) && delta <= window;
}

void add_supporting_event(std::vector<HeuristicSupportingEvent> &events, const TimelineEvent &timeline_event) {
    events.push_back({timeline_event.origin, timeline_event.record});
}

std::string compute_confidence(std::size_t weight) {
    if (weight >= 5) {
        return "High";
    }
    if (weight >= 3) {
        return "Medium";
    }
    return "Low";
}

}  // namespace

std::vector<HeuristicInsight> AnalyzeEventTimeline(const std::vector<TimelineEvent> &events) {
    std::vector<HeuristicInsight> insights;
    if (events.empty()) {
        return insights;
    }

    const EventRecord &last_event = events.back().record;

    // Track aggregated signals for heuristics.
    std::map<std::string, std::size_t> restart_bursts;
    std::size_t security_disabled = 0;
    std::vector<const TimelineEvent *> security_events;
    std::vector<const TimelineEvent *> memory_pressure_events;
    std::vector<const TimelineEvent *> kernel_fault_events;

    for (const auto &event : events) {
        const auto &record = event.record;
        const auto lower_category = record.category;
        if (lower_category == "ServiceHealth") {
            auto state = find_attribute(record, "state");
            auto restarts = find_attribute(record, "restartCount");
            if (state && contains_case_insensitive(*state, "restart")) {
                restart_bursts[event.origin] += 2;
            }
            if (restarts) {
                try {
                    std::size_t count = static_cast<std::size_t>(std::stoull(*restarts));
                    if (count >= 3) {
                        restart_bursts[event.origin] += count;
                    }
                } catch (const std::exception &) {
                }
            }
        }

        if (record.category == "Security") {
            auto state_text = find_attribute(record, "stateText");
            auto vendor = find_attribute(record, "name");
            auto suite = find_attribute(record, "suite");
            const bool disabled = state_text && contains_case_insensitive(*state_text, "Disabled");
            if (disabled) {
                security_disabled += 2;
            }
            if (vendor && contains_case_insensitive(*vendor, "Microsoft")) {
                // Lower weight for Microsoft Defender because it is expected.
            } else if (state_text && contains_case_insensitive(*state_text, "Outdated")) {
                security_disabled += 1;
            }
            if (disabled || (suite && contains_case_insensitive(*suite, "ThirdParty"))) {
                security_events.push_back(&event);
            }
        }

        if (record.category == "Process" || record.category == "Resource") {
            auto message_lower = record.message;
            if (contains_case_insensitive(message_lower, "memory pressure") ||
                contains_case_insensitive(message_lower, "pressure stall")) {
                memory_pressure_events.push_back(&event);
            }
        }

        if (record.category == "Kernel" || record.category == "Kmsg" ||
            contains_case_insensitive(record.message, "panic") ||
            contains_case_insensitive(record.message, "bugcheck")) {
            kernel_fault_events.push_back(&event);
        }
    }

    for (const auto &[origin, weight] : restart_bursts) {
        if (weight == 0) {
            continue;
        }
        HeuristicInsight insight;
        insight.id = origin + "_service_restart_burst";
        insight.summary = "Rapid restart burst detected on " + origin + " service stack";
        insight.rationale = "Multiple ServiceHealth events indicated restart storms shortly before collection halted.";
        insight.confidence = compute_confidence(weight);
        for (const auto &event : events) {
            if (event.origin == origin && event.record.category == "ServiceHealth" &&
                is_recent(last_event, event.record)) {
                add_supporting_event(insight.supporting_events, event);
            }
        }
        if (!insight.supporting_events.empty()) {
            insights.push_back(std::move(insight));
        }
    }

    if (!security_events.empty()) {
        HeuristicInsight insight;
        insight.id = "cross_environment_security_intervention";
        insight.summary = "Third-party security suite intervention suspected";
        insight.rationale =
            "SecurityCenter telemetry reported disabled or outdated states for non-Microsoft products around the shutdown.";
        insight.confidence = compute_confidence(security_disabled + security_events.size());
        for (const auto *event : security_events) {
            if (is_recent(last_event, event->record, std::chrono::minutes(30))) {
                add_supporting_event(insight.supporting_events, *event);
            }
        }
        if (!insight.supporting_events.empty()) {
            insights.push_back(std::move(insight));
        }
    }

    if (!memory_pressure_events.empty()) {
        HeuristicInsight insight;
        insight.id = "memory_pressure_correlation";
        insight.summary = "Sustained memory pressure observed prior to restart";
        insight.rationale =
            "Process and resource collectors recorded elevated working sets or pressure stall metrics leading up to the outage.";
        insight.confidence = compute_confidence(memory_pressure_events.size());
        for (const auto *event : memory_pressure_events) {
            if (is_recent(last_event, event->record)) {
                add_supporting_event(insight.supporting_events, *event);
            }
        }
        if (!insight.supporting_events.empty()) {
            insights.push_back(std::move(insight));
        }
    }

    if (!kernel_fault_events.empty()) {
        HeuristicInsight insight;
        insight.id = "kernel_fault_chain";
        insight.summary = "Kernel faults surfaced within the observation window";
        insight.rationale =
            "Guest kernel messages or Windows bugcheck indicators were emitted close to the shutdown timeline.";
        insight.confidence = compute_confidence(kernel_fault_events.size());
        for (const auto *event : kernel_fault_events) {
            if (is_recent(last_event, event->record, std::chrono::minutes(30))) {
                add_supporting_event(insight.supporting_events, *event);
            }
        }
        if (!insight.supporting_events.empty()) {
            insights.push_back(std::move(insight));
        }
    }

    std::stable_sort(insights.begin(), insights.end(), [](const HeuristicInsight &lhs, const HeuristicInsight &rhs) {
        return lhs.id < rhs.id;
    });
    return insights;
}

CrossChannelHealthSnapshot ComputeCrossChannelSnapshot(const std::vector<TimelineEvent> &events) {
    CrossChannelHealthSnapshot snapshot;
    auto accumulate = [](ChannelHealthMetrics &metrics, const EventRecord &record) {
        if (metrics.total == 0) {
            metrics.first_timestamp = record.timestamp;
            metrics.last_timestamp = record.timestamp;
        } else {
            metrics.first_timestamp = std::min(metrics.first_timestamp, record.timestamp);
            metrics.last_timestamp = std::max(metrics.last_timestamp, record.timestamp);
        }
        metrics.total += 1;
        const auto &severity = record.severity;
        if (severity == "Critical") {
            metrics.critical += 1;
        } else if (severity == "Error") {
            metrics.error += 1;
        } else if (severity == "Warning") {
            metrics.warning += 1;
        } else {
            metrics.info += 1;
        }
    };

    for (const auto &event : events) {
        if (event.origin == "host") {
            accumulate(snapshot.host, event.record);
        } else if (event.origin == "guest") {
            accumulate(snapshot.guest, event.record);
        }
    }
    return snapshot;
}

}  // namespace wslmon

