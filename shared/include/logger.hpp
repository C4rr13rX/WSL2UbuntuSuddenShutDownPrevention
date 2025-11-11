#pragma once

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

#include "event.hpp"

namespace wslmon {

class JsonLogger {
  public:
    explicit JsonLogger(std::filesystem::path log_path);

    void Append(const EventRecord &record);
    void Rotate();

  private:
    void open_stream();

    std::filesystem::path log_path_;
    std::ofstream stream_;
    std::mutex mutex_;
    std::uint64_t next_sequence_ = 1;
};

}  // namespace wslmon

