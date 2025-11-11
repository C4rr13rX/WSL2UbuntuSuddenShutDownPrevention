#include "monitor_daemon.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>
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

}  // namespace wslmon::ubuntu

