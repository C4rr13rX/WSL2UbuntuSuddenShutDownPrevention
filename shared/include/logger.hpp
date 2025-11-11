#pragma once

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#include "event.hpp"

namespace wslmon {

class JsonLogger {
  public:
    explicit JsonLogger(std::filesystem::path log_path, std::string default_source);

    void Append(const EventRecord &record);
    void Rotate();
    [[nodiscard]] const std::string &CurrentChainHash() const { return current_chain_hash_; }

  private:
    void open_stream();
    void load_chain_state();
    void persist_chain_state();
    void ensure_directory_hardening();
    std::string format_timestamp_utc() const;

    std::filesystem::path log_path_;
    std::filesystem::path chain_state_path_;
    std::ofstream stream_;
    std::mutex mutex_;
    std::string default_source_;
    std::vector<std::uint8_t> hmac_key_;
    std::string current_chain_hash_;
    std::uint64_t next_sequence_ = 1;
    std::uint64_t entries_since_rotation_ = 0;
};

}  // namespace wslmon

