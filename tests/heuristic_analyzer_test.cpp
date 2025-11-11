#include "heuristic_analyzer.hpp"

#include <chrono>
#include <iostream>

namespace {
void add_attribute(wslmon::EventRecord &record, const std::string &key, const std::string &value) {
    record.attributes.push_back({key, value});
}
}

int main() {
    using namespace std::chrono;
    using namespace wslmon;

    std::vector<TimelineEvent> events;
    auto now = system_clock::now();

    EventRecord service_event;
    service_event.category = "ServiceHealth";
    service_event.severity = "Warning";
    service_event.timestamp = now - minutes(2);
    add_attribute(service_event, "state", "RestartPending");
    add_attribute(service_event, "restartCount", "4");
    events.push_back({"host", service_event, "hash1"});

    EventRecord security_event;
    security_event.category = "Security";
    security_event.severity = "Warning";
    security_event.timestamp = now - minutes(1);
    add_attribute(security_event, "name", "Contoso Endpoint Shield");
    add_attribute(security_event, "stateText", "Disabled|Outdated");
    events.push_back({"host", security_event, "hash2"});

    EventRecord memory_event;
    memory_event.category = "Process";
    memory_event.severity = "Warning";
    memory_event.timestamp = now - minutes(1);
    memory_event.message = "Tracked process memory pressure";
    add_attribute(memory_event, "name", "vmmem");
    events.push_back({"guest", memory_event, "hash3"});

    EventRecord kernel_event;
    kernel_event.category = "Kernel";
    kernel_event.severity = "Error";
    kernel_event.timestamp = now - minutes(1);
    kernel_event.message = "kernel panic: fatal fault";
    events.push_back({"guest", kernel_event, "hash4"});

    auto insights = AnalyzeEventTimeline(events);
    bool found_restart = false;
    bool found_security = false;
    bool found_memory = false;
    bool found_kernel = false;

    for (const auto &insight : insights) {
        if (insight.id.find("service_restart_burst") != std::string::npos) {
            found_restart = true;
        } else if (insight.id == "cross_environment_security_intervention") {
            found_security = true;
        } else if (insight.id == "memory_pressure_correlation") {
            found_memory = true;
        } else if (insight.id == "kernel_fault_chain") {
            found_kernel = true;
        }
    }

    if (!found_restart || !found_security || !found_memory || !found_kernel) {
        std::cerr << "Heuristic coverage missing\n";
        return 1;
    }

    auto snapshot = ComputeCrossChannelSnapshot(events);
    if (snapshot.host.total != 2 || snapshot.guest.total != 2) {
        std::cerr << "Cross-channel totals incorrect\n";
        return 1;
    }
    if (snapshot.host.warning == 2 && snapshot.guest.warning >= 1) {
        return 0;
    }
    std::cerr << "Severity aggregation unexpected\n";
    return 1;
}
