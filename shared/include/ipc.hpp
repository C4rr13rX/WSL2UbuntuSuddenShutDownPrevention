#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "event.hpp"

namespace wslmon {

using IpcReadFn = std::function<bool(std::uint8_t *buffer, std::size_t bytes)>;
using IpcWriteFn = std::function<bool(const std::uint8_t *buffer, std::size_t bytes)>;

std::array<std::uint8_t, 32> GenerateNonce();

bool IpcServerHandshake(const IpcWriteFn &write_fn,
                        const IpcReadFn &read_fn,
                        const std::vector<std::uint8_t> &shared_secret,
                        std::vector<std::uint8_t> &session_key);

bool IpcClientHandshake(const IpcWriteFn &write_fn,
                        const IpcReadFn &read_fn,
                        const std::vector<std::uint8_t> &shared_secret,
                        std::vector<std::uint8_t> &session_key);

bool IpcSendEvent(const IpcWriteFn &write_fn,
                  const std::vector<std::uint8_t> &session_key,
                  const EventRecord &record);

bool IpcReceiveEvent(const IpcReadFn &read_fn,
                     const std::vector<std::uint8_t> &session_key,
                     EventRecord &out_record);

}  // namespace wslmon

