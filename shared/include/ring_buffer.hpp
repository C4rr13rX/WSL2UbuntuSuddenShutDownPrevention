#pragma once

#include <cstddef>
#include <mutex>
#include <optional>
#include <vector>

namespace wslmon {

template <typename T>
class RingBuffer {
  public:
    explicit RingBuffer(std::size_t capacity)
        : capacity_(capacity), buffer_(capacity) {}

    void Push(T value) {
        std::lock_guard<std::mutex> lock(mutex_);
        buffer_[write_index_] = std::move(value);
        write_index_ = (write_index_ + 1) % capacity_;
        if (size_ < capacity_) {
            ++size_;
        } else {
            read_index_ = write_index_;
        }
    }

    std::vector<T> Snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<T> out;
        out.reserve(size_);
        for (std::size_t i = 0; i < size_; ++i) {
            std::size_t index = (read_index_ + i) % capacity_;
            out.push_back(buffer_[index]);
        }
        return out;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return size_;
    }

  private:
    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::vector<T> buffer_;
    std::size_t write_index_ = 0;
    std::size_t read_index_ = 0;
    std::size_t size_ = 0;
};

}  // namespace wslmon

