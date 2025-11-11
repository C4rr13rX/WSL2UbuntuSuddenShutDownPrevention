#include "logger.hpp"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <sstream>

namespace wslmon {

namespace {
constexpr std::size_t kMaxLogSizeBytes = 5 * 1024 * 1024;

std::string format_rotation_suffix() {
    auto now = std::chrono::system_clock::now();
    auto time_t_value = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &time_t_value);
#else
    gmtime_r(&time_t_value, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%dT%H%M%SZ");
    return oss.str();
}
}  // namespace

JsonLogger::JsonLogger(std::filesystem::path log_path)
    : log_path_(std::move(log_path)) {
    open_stream();
}

void JsonLogger::open_stream() {
    std::filesystem::create_directories(log_path_.parent_path());
    stream_.open(log_path_, std::ios::out | std::ios::app);
}

void JsonLogger::Append(const EventRecord &record) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!stream_.is_open()) {
        open_stream();
    }
    EventRecord enriched = record;
    if (enriched.sequence == 0) {
        enriched.sequence = next_sequence_++;
    } else if (enriched.sequence >= next_sequence_) {
        next_sequence_ = enriched.sequence + 1;
    }
    stream_ << SerializeEvent(enriched) << '\n';
    stream_.flush();

    if (stream_.tellp() > static_cast<std::streamoff>(kMaxLogSizeBytes)) {
        Rotate();
    }
}

void JsonLogger::Rotate() {
    stream_.close();
    auto rotated_name = log_path_;
    rotated_name += '.' + format_rotation_suffix();
    std::error_code ec;
    std::filesystem::rename(log_path_, rotated_name, ec);
    open_stream();
}

}  // namespace wslmon

