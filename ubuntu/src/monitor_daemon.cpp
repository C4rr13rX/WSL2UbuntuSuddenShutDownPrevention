#include "monitor_daemon.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>
#include <cstdio>
#include <cerrno>

#include <systemd/sd-journal.h>

namespace wslmon::ubuntu {

namespace {
std::string read_trimmed_file(const std::filesystem::path &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return {};
    }
    std::string value;
    std::getline(file, value);
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
        value.pop_back();
    }
    return value;
}

std::string detect_hostname() {
    std::array<char, 256> buffer{};
    if (gethostname(buffer.data(), buffer.size()) == 0) {
        return std::string(buffer.data());
    }
    return {};
}

std::string get_journal_field(sd_journal *journal, const char *field) {
    const void *data = nullptr;
    size_t length = 0;
    if (sd_journal_get_data(journal, field, &data, &length) < 0 || !data) {
        return {};
    }
    const char *raw = static_cast<const char *>(data);
    const char *value = std::strchr(raw, '=');
    if (!value) {
        return {};
    }
    return std::string(value + 1);
}

std::string trim_newlines(std::string input) {
    while (!input.empty() && (input.back() == '\n' || input.back() == '\r')) {
        input.pop_back();
    }
    return input;
}

std::string to_lower_copy(std::string input) {
    std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return input;
}

bool contains_any_keyword(const std::string &line, const std::vector<std::string> &keywords) {
    const std::string lowered = to_lower_copy(line);
    for (const auto &keyword : keywords) {
        if (lowered.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

struct PressureReading {
    double avg10 = 0.0;
    double avg60 = 0.0;
    double avg300 = 0.0;
};

bool parse_pressure_file(const std::string &path, PressureReading &some, PressureReading &full) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string scope;
        iss >> scope;
        std::string token;
        PressureReading reading;
        while (iss >> token) {
            auto pos = token.find('=');
            if (pos == std::string::npos) {
                continue;
            }
            std::string key = token.substr(0, pos);
            std::string value = token.substr(pos + 1);
            try {
                if (key == "avg10") {
                    reading.avg10 = std::stod(value);
                } else if (key == "avg60") {
                    reading.avg60 = std::stod(value);
                } else if (key == "avg300") {
                    reading.avg300 = std::stod(value);
                }
            } catch (const std::exception &) {
                continue;
            }
        }
        if (scope == "some") {
            some = reading;
        } else if (scope == "full") {
            full = reading;
        }
    }
    return true;
}

struct InterfaceCounters {
    std::uint64_t rx_bytes = 0;
    std::uint64_t rx_errors = 0;
    std::uint64_t rx_dropped = 0;
    std::uint64_t tx_bytes = 0;
    std::uint64_t tx_errors = 0;
    std::uint64_t tx_dropped = 0;
};

bool parse_interface_line(const std::string &line, std::string &name, InterfaceCounters &counters) {
    auto colon_pos = line.find(':');
    if (colon_pos == std::string::npos) {
        return false;
    }
    name = line.substr(0, colon_pos);
    name.erase(0, name.find_first_not_of(" \t"));
    name.erase(name.find_last_not_of(" \t") + 1);
    std::istringstream iss(line.substr(colon_pos + 1));
    iss >> counters.rx_bytes;  // bytes
    std::uint64_t rx_packets = 0;
    iss >> rx_packets >> counters.rx_errors >> counters.rx_dropped;
    // skip fifo frame compressed multicast
    std::uint64_t skip = 0;
    iss >> skip >> skip >> skip >> skip;
    iss >> counters.tx_bytes;
    std::uint64_t tx_packets = 0;
    iss >> tx_packets >> counters.tx_errors >> counters.tx_dropped;
    return !name.empty();
}

struct CpuSample {
    std::uint64_t user = 0;
    std::uint64_t nice = 0;
    std::uint64_t system = 0;
    std::uint64_t idle = 0;
    std::uint64_t iowait = 0;
    std::uint64_t irq = 0;
    std::uint64_t softirq = 0;
};

bool read_cpu_sample(CpuSample &sample) {
    std::ifstream stat("/proc/stat");
    if (!stat.is_open()) {
        return false;
    }
    std::string cpu;
    stat >> cpu >> sample.user >> sample.nice >> sample.system >> sample.idle >> sample.iowait >> sample.irq >> sample.softirq;
    return cpu == "cpu";
}

double compute_cpu_usage(const CpuSample &prev, const CpuSample &curr) {
    std::uint64_t prev_idle = prev.idle + prev.iowait;
    std::uint64_t curr_idle = curr.idle + curr.iowait;
    std::uint64_t prev_total = prev_idle + prev.user + prev.nice + prev.system + prev.irq + prev.softirq;
    std::uint64_t curr_total = curr_idle + curr.user + curr.nice + curr.system + curr.irq + curr.softirq;
    std::uint64_t totald = curr_total - prev_total;
    std::uint64_t idled = curr_idle - prev_idle;
    if (totald == 0) {
        return 0.0;
    }
    return (static_cast<double>(totald - idled) / static_cast<double>(totald)) * 100.0;
}

bool read_memory_usage(double &used_percent) {
    std::ifstream meminfo("/proc/meminfo");
    if (!meminfo.is_open()) {
        return false;
    }
    std::uint64_t mem_total = 0;
    std::uint64_t mem_available = 0;
    std::string key;
    std::uint64_t value;
    std::string unit;
    while (meminfo >> key >> value >> unit) {
        if (key == "MemTotal:") {
            mem_total = value;
        } else if (key == "MemAvailable:") {
            mem_available = value;
        }
    }
    if (mem_total == 0) {
        return false;
    }
    used_percent = (static_cast<double>(mem_total - mem_available) / static_cast<double>(mem_total)) * 100.0;
    return true;
}

void add_journal_matches(sd_journal *journal) {
    sd_journal_add_match(journal, "SYSLOG_IDENTIFIER=systemd", 0);
    sd_journal_add_match(journal, "SYSLOG_IDENTIFIER=kernel", 0);
    sd_journal_add_match(journal, "SYSLOG_IDENTIFIER=systemd-oomd", 0);
    sd_journal_add_match(journal, "_SYSTEMD_UNIT=systemd-networkd.service", 0);
    sd_journal_add_match(journal, "_SYSTEMD_UNIT=systemd-resolved.service", 0);
    sd_journal_add_match(journal, "_SYSTEMD_UNIT=systemd-logind.service", 0);
    sd_journal_add_match(journal, "_SYSTEMD_UNIT=systemd", 0);
    sd_journal_add_match(journal, "_TRANSPORT=kernel", 0);
}

}  // namespace

MonitorDaemon::MonitorDaemon()
    : logger_(std::filesystem::path{"/var/log/wsl-monitor/guest-events.log"}, "wslmon.ubuntu"),
      buffer_(1024),
      boot_id_(read_trimmed_file("/proc/sys/kernel/random/boot_id")),
      machine_id_(read_trimmed_file("/etc/machine-id")),
      hostname_(detect_hostname()) {}

MonitorDaemon::~MonitorDaemon() { Stop(); }

void MonitorDaemon::Run() {
    if (running_.exchange(true)) {
        return;
    }
    workers_.emplace_back(&MonitorDaemon::watch_journal, this);
    workers_.emplace_back(&MonitorDaemon::watch_resources, this);
    workers_.emplace_back(&MonitorDaemon::watch_crashes, this);
    workers_.emplace_back(&MonitorDaemon::watch_kmsg, this);
    workers_.emplace_back(&MonitorDaemon::watch_pressure, this);
    workers_.emplace_back(&MonitorDaemon::watch_systemd_failures, this);
    workers_.emplace_back(&MonitorDaemon::watch_network_health, this);
}

void MonitorDaemon::Stop() {
    if (!running_.exchange(false)) {
        return;
    }
    for (auto &worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

void MonitorDaemon::emit(EventRecord record) {
    record.timestamp = std::chrono::system_clock::now();
    add_common_attributes(record);
    buffer_.Push(record);
    logger_.Append(record);
}

void MonitorDaemon::add_common_attributes(EventRecord &record) {
    auto ensure_attr = [&record](const std::string &key, const std::string &value) {
        if (value.empty()) {
            return;
        }
        auto existing = std::find_if(record.attributes.begin(), record.attributes.end(),
                                      [&key](const auto &attr) { return attr.key == key; });
        if (existing == record.attributes.end()) {
            record.attributes.push_back({key, value});
        }
    };

    ensure_attr("boot_id", boot_id_);
    ensure_attr("machine_id", machine_id_);
    ensure_attr("hostname", hostname_);
}

void MonitorDaemon::watch_journal() {
    sd_journal *journal = nullptr;
    if (sd_journal_open(&journal, SD_JOURNAL_LOCAL_ONLY) < 0) {
        EventRecord record;
        record.source = "systemd.journal";
        record.category = "Journal";
        record.severity = "Error";
        record.message = "Failed to open systemd journal";
        emit(std::move(record));
        return;
    }
    add_journal_matches(journal);
    sd_journal_seek_tail(journal);
    sd_journal_previous_skip(journal, 10);

    while (running_.load()) {
        int wait_result = sd_journal_wait(journal, 5 * 1000 * 1000);
        if (wait_result < 0) {
            break;
        }
        while (sd_journal_next(journal) > 0) {
            EventRecord record;
            record.source = "systemd.journal";
            record.category = "Journal";
            record.severity = "Info";
            record.message = trim_newlines(get_journal_field(journal, "MESSAGE"));
            record.attributes.push_back({"unit", get_journal_field(journal, "_SYSTEMD_UNIT")});
            record.attributes.push_back({"transport", get_journal_field(journal, "_TRANSPORT")});
            record.attributes.push_back({"priority", get_journal_field(journal, "PRIORITY")});
            emit(std::move(record));
        }
    }
    sd_journal_close(journal);
}

void MonitorDaemon::watch_resources() {
    CpuSample prev{};
    if (!read_cpu_sample(prev)) {
        EventRecord record;
        record.source = "resource.monitor";
        record.category = "Resource";
        record.severity = "Warning";
        record.message = "Unable to read initial CPU sample";
        emit(std::move(record));
    }
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        CpuSample curr{};
        if (!read_cpu_sample(curr)) {
            continue;
        }
        double cpu_usage = compute_cpu_usage(prev, curr);
        prev = curr;
        double mem_usage = 0.0;
        read_memory_usage(mem_usage);

        struct statvfs vfs {};
        double root_usage = 0.0;
        if (statvfs("/", &vfs) == 0) {
            auto total = static_cast<double>(vfs.f_blocks) * vfs.f_frsize;
            auto available = static_cast<double>(vfs.f_bavail) * vfs.f_frsize;
            if (total > 0) {
                root_usage = (total - available) / total * 100.0;
            }
        }

        EventRecord record;
        record.source = "resource.monitor";
        record.category = "Resource";
        record.severity = "Info";
        record.message = "Resource utilization";
        record.attributes.push_back({"cpu", std::to_string(cpu_usage)});
        record.attributes.push_back({"mem", std::to_string(mem_usage)});
        record.attributes.push_back({"disk_root", std::to_string(root_usage)});
        emit(std::move(record));
    }
}

void MonitorDaemon::watch_crashes() {
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        EventRecord record;
        record.source = "inotify.crash";
        record.category = "Crash";
        record.severity = "Error";
        record.message = "Failed to initialize inotify";
        record.attributes.push_back({"error", std::to_string(errno)});
        emit(std::move(record));
        return;
    }
    int wd = inotify_add_watch(fd, "/var/crash", IN_CREATE | IN_MOVED_TO);
    if (wd < 0) {
        EventRecord record;
        record.source = "inotify.crash";
        record.category = "Crash";
        record.severity = "Warning";
        record.message = "Cannot watch /var/crash";
        record.attributes.push_back({"error", std::to_string(errno)});
        emit(std::move(record));
    }

    std::vector<char> buffer(4096);
    while (running_.load()) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int result = poll(&pfd, 1, 1000);
        if (result > 0 && (pfd.revents & POLLIN)) {
            int bytes = read(fd, buffer.data(), buffer.size());
            if (bytes > 0) {
                int offset = 0;
                while (offset < bytes) {
                    auto *event = reinterpret_cast<inotify_event *>(buffer.data() + offset);
                    if (event->len > 0) {
                        EventRecord record;
                        record.source = "inotify.crash";
                        record.category = "Crash";
                        record.severity = "Critical";
                        record.message = "Crash dump detected";
                        record.attributes.push_back({"path", std::string("/var/crash/") + event->name});
                        emit(std::move(record));
                    }
                    offset += sizeof(inotify_event) + event->len;
                }
            }
        }
    }
    if (wd >= 0) {
        inotify_rm_watch(fd, wd);
    }
    close(fd);
}

void MonitorDaemon::watch_kmsg() {
    int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        EventRecord record;
        record.source = "kernel.kmsg";
        record.category = "Kernel";
        record.severity = "Warning";
        record.message = "Unable to open /dev/kmsg";
        record.attributes.push_back({"error", std::to_string(errno)});
        emit(std::move(record));
        return;
    }

    std::vector<char> buffer(4096);
    while (running_.load()) {
        ssize_t bytes = read(fd, buffer.data(), buffer.size() - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::istringstream iss(buffer.data());
            std::string line;
            while (std::getline(iss, line)) {
                if (line.empty()) {
                    continue;
                }
                std::string trimmed = trim_newlines(line);
                EventRecord record;
                record.source = "kernel.kmsg";
                record.category = "Kernel";
                record.message = trimmed;
                if (contains_any_keyword(trimmed, {"panic", "fatal", "bug"})) {
                    record.severity = "Critical";
                } else if (contains_any_keyword(trimmed, {"error", "warn", "oom"})) {
                    record.severity = "Warning";
                } else {
                    record.severity = "Info";
                }
                emit(std::move(record));
            }
        } else if (bytes == 0) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } else {
            if (errno != EAGAIN) {
                EventRecord record;
                record.source = "kernel.kmsg";
                record.category = "Kernel";
                record.severity = "Warning";
                record.message = "kmsg read failure";
                record.attributes.push_back({"error", std::to_string(errno)});
                emit(std::move(record));
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    close(fd);
}

void MonitorDaemon::watch_pressure() {
    PressureReading some{};
    PressureReading full{};
    PressureReading last_some{};
    PressureReading last_full{};

    while (running_.load()) {
        if (parse_pressure_file("/proc/pressure/memory", some, full)) {
            if ((some.avg10 > 40.0 && some.avg10 > last_some.avg10 + 5.0) || some.avg60 > 30.0 || full.avg10 > 5.0) {
                EventRecord record;
                record.source = "pressure.memory";
                record.category = "Pressure";
                record.severity = some.avg10 > 60.0 || full.avg10 > 10.0 ? "Critical" : "Warning";
                record.message = "Memory pressure elevated";
                record.attributes.push_back({"some_avg10", std::to_string(some.avg10)});
                record.attributes.push_back({"some_avg60", std::to_string(some.avg60)});
                record.attributes.push_back({"full_avg10", std::to_string(full.avg10)});
                record.attributes.push_back({"full_avg60", std::to_string(full.avg60)});
                emit(std::move(record));
            }
            last_some = some;
            last_full = full;
        }

        if (parse_pressure_file("/proc/pressure/cpu", some, full)) {
            if (some.avg10 > 60.0 || full.avg10 > 20.0) {
                EventRecord record;
                record.source = "pressure.cpu";
                record.category = "Pressure";
                record.severity = some.avg10 > 80.0 ? "Critical" : "Warning";
                record.message = "CPU pressure sustained";
                record.attributes.push_back({"some_avg10", std::to_string(some.avg10)});
                record.attributes.push_back({"some_avg60", std::to_string(some.avg60)});
                record.attributes.push_back({"full_avg10", std::to_string(full.avg10)});
                record.attributes.push_back({"full_avg60", std::to_string(full.avg60)});
                emit(std::move(record));
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void MonitorDaemon::watch_systemd_failures() {
    std::string last_output;
    while (running_.load()) {
        FILE *pipe = popen("systemctl --failed --no-legend --plain 2>/dev/null", "r");
        if (!pipe) {
            EventRecord record;
            record.source = "systemd.failures";
            record.category = "Systemd";
            record.severity = "Warning";
            record.message = "Failed to execute systemctl";
            record.attributes.push_back({"error", std::to_string(errno)});
            emit(std::move(record));
            std::this_thread::sleep_for(std::chrono::seconds(30));
            continue;
        }
        std::string output;
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe)) {
            output += buffer;
        }
        int status = pclose(pipe);
        if (status == 0 && !output.empty() && output != last_output) {
            EventRecord record;
            record.source = "systemd.failures";
            record.category = "Systemd";
            record.severity = "Warning";
            record.message = "Systemd units failing";
            record.attributes.push_back({"units", trim_newlines(output)});
            emit(std::move(record));
            last_output = output;
        } else if (output.empty()) {
            last_output.clear();
        }
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

void MonitorDaemon::watch_network_health() {
    std::unordered_map<std::string, InterfaceCounters> last_state;

    while (running_.load()) {
        std::ifstream dev("/proc/net/dev");
        if (!dev.is_open()) {
            EventRecord record;
            record.source = "net.dev";
            record.category = "Network";
            record.severity = "Warning";
            record.message = "Cannot open /proc/net/dev";
            emit(std::move(record));
            std::this_thread::sleep_for(std::chrono::seconds(15));
            continue;
        }
        std::string line;
        std::getline(dev, line);
        std::getline(dev, line);
        while (std::getline(dev, line)) {
            std::string name;
            InterfaceCounters counters;
            if (!parse_interface_line(line, name, counters)) {
                continue;
            }
            if (name == "lo") {
                continue;
            }
            auto it = last_state.find(name);
            if (it != last_state.end()) {
                auto &prev = it->second;
                auto rx_drop_delta = counters.rx_dropped - prev.rx_dropped;
                auto tx_drop_delta = counters.tx_dropped - prev.tx_dropped;
                auto rx_err_delta = counters.rx_errors - prev.rx_errors;
                auto tx_err_delta = counters.tx_errors - prev.tx_errors;
                if (rx_drop_delta > 0 || tx_drop_delta > 0 || rx_err_delta > 0 || tx_err_delta > 0) {
                    EventRecord record;
                    record.source = "net.dev";
                    record.category = "Network";
                    record.severity = (rx_err_delta + tx_err_delta) > 0 ? "Warning" : "Info";
                    record.message = "Interface error counters increased";
                    record.attributes.push_back({"interface", name});
                    record.attributes.push_back({"rx_dropped", std::to_string(rx_drop_delta)});
                    record.attributes.push_back({"tx_dropped", std::to_string(tx_drop_delta)});
                    record.attributes.push_back({"rx_errors", std::to_string(rx_err_delta)});
                    record.attributes.push_back({"tx_errors", std::to_string(tx_err_delta)});
                    record.attributes.push_back({"rx_bytes", std::to_string(counters.rx_bytes)});
                    record.attributes.push_back({"tx_bytes", std::to_string(counters.tx_bytes)});
                    emit(std::move(record));
                }
            }
            last_state[name] = counters;
        }
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
}

}  // namespace wslmon::ubuntu

