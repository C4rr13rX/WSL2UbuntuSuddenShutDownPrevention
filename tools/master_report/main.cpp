#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <ctime>

#include "event.hpp"
#include "heuristic_analyzer.hpp"

namespace {
struct ReportOptions {
    std::filesystem::path host_log;
    std::filesystem::path guest_log;
    std::filesystem::path output_path;
};

struct CollectedEvent {
    wslmon::TimelineEvent timeline;
    std::string event_json;
};

std::string now_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_value = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &time_t_value);
#else
    gmtime_r(&time_t_value, &tm);
#endif
    auto fractional = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count() % 1000000;
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setw(6) << std::setfill('0') << fractional << 'Z';
    return oss.str();
}

bool extract_event_json(const std::string &line, std::string &event_json, std::string &chain_hash) {
    auto event_pos = line.find("\"event\":");
    if (event_pos == std::string::npos) {
        return false;
    }
    auto brace_pos = line.find('{', event_pos);
    if (brace_pos == std::string::npos) {
        return false;
    }
    int depth = 0;
    std::size_t end_pos = std::string::npos;
    for (std::size_t i = brace_pos; i < line.size(); ++i) {
        if (line[i] == '{') {
            ++depth;
        } else if (line[i] == '}') {
            --depth;
            if (depth == 0) {
                end_pos = i;
                break;
            }
        }
    }
    if (end_pos == std::string::npos) {
        return false;
    }
    event_json = line.substr(brace_pos, end_pos - brace_pos + 1);

    auto chain_pos = line.find("\"chainHash\":\"", end_pos);
    if (chain_pos != std::string::npos) {
        chain_pos += std::string("\"chainHash\":\"").size();
        auto chain_end = line.find('"', chain_pos);
        if (chain_end != std::string::npos) {
            chain_hash = line.substr(chain_pos, chain_end - chain_pos);
        }
    }
    return true;
}

bool load_log(const std::filesystem::path &path, const std::string &origin, std::vector<CollectedEvent> &events,
              std::string &final_chain_hash) {
    std::ifstream in(path);
    if (!in.is_open()) {
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        std::string event_json;
        std::string chain_hash;
        if (!extract_event_json(line, event_json, chain_hash)) {
            continue;
        }
        final_chain_hash = chain_hash;
        wslmon::EventRecord record;
        if (!wslmon::DeserializeEvent(event_json, record)) {
            continue;
        }
        events.push_back(CollectedEvent{wslmon::TimelineEvent{origin, std::move(record), chain_hash}, event_json});
    }
    return true;
}

ReportOptions parse_arguments(int argc, char **argv) {
    ReportOptions options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--host-log" && i + 1 < argc) {
            options.host_log = argv[++i];
        } else if (arg == "--guest-log" && i + 1 < argc) {
            options.guest_log = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            options.output_path = argv[++i];
        } else if (arg == "--help") {
            std::cout << "Usage: master_report --host-log <path> --guest-log <path> [--output <path>]\n";
            std::exit(0);
        }
    }
    if (options.host_log.empty()) {
#ifdef _WIN32
        options.host_log = "C:/ProgramData/WslMonitor/host-events.log";
#else
        options.host_log = "/mnt/c/ProgramData/WslMonitor/host-events.log";
#endif
    }
    if (options.guest_log.empty()) {
#ifdef _WIN32
        options.guest_log = "C:/ProgramData/WslMonitor/guest-events.log";
#else
        options.guest_log = "/var/log/wsl-monitor/guest-events.log";
#endif
    }
    return options;
}

std::string format_timestamp(const std::chrono::system_clock::time_point &tp) {
    if (tp == std::chrono::system_clock::time_point{}) {
        return "";
    }
    auto time_t_value = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &time_t_value);
#else
    gmtime_r(&time_t_value, &tm);
#endif
    auto fractional = std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()).count() % 1000000;
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setw(6) << std::setfill('0') << fractional << 'Z';
    return oss.str();
}

void append_metrics(std::ostringstream &oss, const wslmon::ChannelHealthMetrics &metrics) {
    oss << "{\"total\":" << metrics.total;
    oss << ",\"info\":" << metrics.info;
    oss << ",\"warning\":" << metrics.warning;
    oss << ",\"error\":" << metrics.error;
    oss << ",\"critical\":" << metrics.critical;
    if (metrics.total > 0) {
        oss << ",\"firstTimestamp\":\"" << format_timestamp(metrics.first_timestamp) << "\"";
        oss << ",\"lastTimestamp\":\"" << format_timestamp(metrics.last_timestamp) << "\"";
    }
    oss << '}';
}

void write_report(const std::vector<CollectedEvent> &events, const ReportOptions &options, const std::string &host_chain,
                  const std::string &guest_chain) {
    std::vector<wslmon::TimelineEvent> timeline;
    timeline.reserve(events.size());
    for (const auto &entry : events) {
        timeline.push_back(entry.timeline);
    }

    const auto health = wslmon::ComputeCrossChannelSnapshot(timeline);
    const auto insights = wslmon::AnalyzeEventTimeline(timeline);

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"generatedAt\": \"" << now_timestamp() << "\",\n";
    oss << "  \"host\": {\n";
    oss << "    \"logPath\": \"" << options.host_log.string() << "\",\n";
    oss << "    \"finalChainHash\": \"" << host_chain << "\",\n";
    oss << "    \"eventCount\": " << std::count_if(events.begin(), events.end(), [](const auto &e) {
        return e.timeline.origin == "host";
    }) << "\n";
    oss << "  },\n";
    oss << "  \"guest\": {\n";
    oss << "    \"logPath\": \"" << options.guest_log.string() << "\",\n";
    oss << "    \"finalChainHash\": \"" << guest_chain << "\",\n";
    oss << "    \"eventCount\": " << std::count_if(events.begin(), events.end(), [](const auto &e) {
        return e.timeline.origin == "guest";
    }) << "\n";
    oss << "  },\n";
    oss << "  \"health\": {\n";
    oss << "    \"host\": ";
    append_metrics(oss, health.host);
    oss << ",\n";
    oss << "    \"guest\": ";
    append_metrics(oss, health.guest);
    oss << "\n  },\n";
    oss << "  \"analysis\": {\n";
    oss << "    \"insights\": [\n";
    for (std::size_t i = 0; i < insights.size(); ++i) {
        const auto &insight = insights[i];
        oss << "      {\"id\":\"" << insight.id << "\",\"summary\":\"" << insight.summary
            << "\",\"rationale\":\"" << insight.rationale << "\",\"confidence\":\"" << insight.confidence
            << "\",\"supportingEvents\":[";
        for (std::size_t j = 0; j < insight.supporting_events.size(); ++j) {
            const auto &support = insight.supporting_events[j];
            oss << "{\"origin\":\"" << support.origin << "\",\"event\":"
                << wslmon::SerializeEvent(support.record) << "}";
            if (j + 1 < insight.supporting_events.size()) {
                oss << ',';
            }
        }
        oss << "]}";
        if (i + 1 < insights.size()) {
            oss << ',';
        }
        oss << '\n';
    }
    oss << "    ]\n";
    oss << "  },\n";
    oss << "  \"events\": [\n";
    for (std::size_t i = 0; i < events.size(); ++i) {
        const auto &event = events[i];
        oss << "    {\"origin\":\"" << event.timeline.origin << "\",\"chainHash\":\""
            << event.timeline.chain_hash << "\",\"event\":" << event.event_json << "}";
        if (i + 1 < events.size()) {
            oss << ',';
        }
        oss << '\n';
    }
    oss << "  ]\n";
    oss << "}\n";

    if (!options.output_path.empty()) {
        std::ofstream out(options.output_path);
        out << oss.str();
    } else {
        std::cout << oss.str();
    }
}

}  // namespace

int main(int argc, char **argv) {
    ReportOptions options = parse_arguments(argc, argv);

    std::vector<CollectedEvent> events;
    events.reserve(4096);

    std::string host_chain;
    std::string guest_chain;

    if (!options.host_log.empty()) {
        if (!load_log(options.host_log, "host", events, host_chain)) {
            std::cerr << "Warning: unable to load host log from " << options.host_log << "\n";
        }
    }
    if (!options.guest_log.empty()) {
        if (!load_log(options.guest_log, "guest", events, guest_chain)) {
            std::cerr << "Warning: unable to load guest log from " << options.guest_log << "\n";
        }
    }

    std::sort(events.begin(), events.end(), [](const CollectedEvent &lhs, const CollectedEvent &rhs) {
        return lhs.timeline.record.timestamp < rhs.timeline.record.timestamp;
    });

    write_report(events, options, host_chain, guest_chain);
    return 0;
}
