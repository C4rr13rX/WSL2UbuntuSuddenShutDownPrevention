#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wslmon {

std::array<std::uint8_t, 32> Sha256(const std::uint8_t *data, std::size_t len);
std::array<std::uint8_t, 32> Sha256(std::string_view data);
std::vector<std::uint8_t> HmacSha256(const std::vector<std::uint8_t> &key,
                                     const std::uint8_t *data,
                                     std::size_t len);
std::string BytesToHex(const std::uint8_t *data, std::size_t len);
std::vector<std::uint8_t> HexToBytes(std::string_view hex);

}  // namespace wslmon

