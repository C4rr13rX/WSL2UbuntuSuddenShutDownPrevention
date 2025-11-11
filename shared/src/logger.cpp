#include "logger.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>

#include "crypto.hpp"

namespace wslmon {

namespace {
constexpr std::size_t kMaxLogSizeBytes = 5 * 1024 * 1024;
const std::string kZeroHash(64, '0');

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

std::vector<std::uint8_t> load_hmac_key_from_env() {
    const char *hex = std::getenv("WSLMON_LOG_HMAC_KEY");
    if (hex && *hex) {
        try {
            return HexToBytes(hex);
        } catch (const std::exception &) {
        }
    }
    const char *file = std::getenv("WSLMON_LOG_HMAC_KEY_FILE");
    if (file && *file) {
        std::ifstream in(file, std::ios::binary);
        if (in) {
            std::ostringstream buffer;
            buffer << in.rdbuf();
            try {
                return HexToBytes(buffer.str());
            } catch (const std::exception &) {
            }
        }
    }
    return {};
}

}  // namespace

JsonLogger::JsonLogger(std::filesystem::path log_path, std::string default_source)
    : log_path_(std::move(log_path)),
      chain_state_path_(log_path_),
      default_source_(std::move(default_source)),
      hmac_key_(load_hmac_key_from_env()),
      current_chain_hash_(kZeroHash) {
    chain_state_path_ += ".chainstate";
    ensure_directory_hardening();
    load_chain_state();
    open_stream();
}

void JsonLogger::ensure_directory_hardening() {
    const auto directory = log_path_.parent_path();
    if (directory.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
#ifndef _WIN32
    std::filesystem::permissions(directory,
                                  std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                      std::filesystem::perms::owner_exec | std::filesystem::perms::group_read |
                                      std::filesystem::perms::group_exec,
                                  std::filesystem::perm_options::add,
                                  ec);
#else
    (void)ec;
#endif
}

void JsonLogger::open_stream() {
    stream_.open(log_path_, std::ios::out | std::ios::app | std::ios::binary);
}

void JsonLogger::load_chain_state() {
    std::ifstream in(chain_state_path_);
    if (!in) {
        current_chain_hash_ = kZeroHash;
        next_sequence_ = 1;
        entries_since_rotation_ = 0;
        return;
    }
    in >> current_chain_hash_ >> next_sequence_ >> entries_since_rotation_;
    if (current_chain_hash_.size() != 64) {
        current_chain_hash_ = kZeroHash;
    }
    if (next_sequence_ == 0) {
        next_sequence_ = 1;
    }
}

void JsonLogger::persist_chain_state() {
    std::ofstream out(chain_state_path_, std::ios::out | std::ios::trunc | std::ios::binary);
    out << current_chain_hash_ << '\n' << next_sequence_ << '\n' << entries_since_rotation_ << '\n';
}

std::string JsonLogger::format_timestamp_utc() const {
    auto now = std::chrono::system_clock::now();
    auto time_t_value = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &time_t_value);
#else
    gmtime_r(&time_t_value, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

void JsonLogger::Append(const EventRecord &record) {
    auto now = std::chrono::system_clock::now();
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
    if (enriched.timestamp.time_since_epoch().count() == 0) {
        enriched.timestamp = now;
    }
    if (enriched.source.empty()) {
        enriched.source = default_source_;
    }
    if (enriched.category.empty()) {
        enriched.category = "General";
    }
    if (enriched.severity.empty()) {
        enriched.severity = "Info";
    }

    const std::string payload = SerializeEvent(enriched);
    const std::string hash_input = current_chain_hash_ + payload;
    const auto chain_bytes = Sha256(reinterpret_cast<const std::uint8_t *>(hash_input.data()), hash_input.size());
    current_chain_hash_ = BytesToHex(chain_bytes.data(), chain_bytes.size());

    std::string hmac_hex;
    if (!hmac_key_.empty()) {
        const auto hmac = HmacSha256(hmac_key_, reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());
        hmac_hex = BytesToHex(hmac.data(), hmac.size());
    }

    stream_ << '{' << "\"event\":" << payload << ",\"chainHash\":\"" << current_chain_hash_ << "\"";
    if (!hmac_hex.empty()) {
        stream_ << ",\"hmac\":\"" << hmac_hex << "\"";
    }
    stream_ << "}\n";
    stream_.flush();

    ++entries_since_rotation_;
    persist_chain_state();

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

    std::filesystem::path manifest_path = rotated_name;
    manifest_path += ".manifest";
    std::ofstream manifest(manifest_path, std::ios::out | std::ios::trunc | std::ios::binary);
    manifest << "{\n";
    manifest << "  \"finalChainHash\": \"" << current_chain_hash_ << "\",\n";
    manifest << "  \"entries\": " << entries_since_rotation_ << ",\n";
    manifest << "  \"rotatedAt\": \"" << format_timestamp_utc() << "\"\n";
    manifest << "}\n";
    manifest.close();

    current_chain_hash_ = kZeroHash;
    entries_since_rotation_ = 0;
    next_sequence_ = 1;
    persist_chain_state();
    open_stream();
}

}  // namespace wslmon

