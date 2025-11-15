#include "crypto.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace wslmon {
namespace {

constexpr std::array<std::uint32_t, 8> kInitHash = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

inline std::uint32_t RightRotate(std::uint32_t value, std::uint32_t bits) {
    return (value >> bits) | (value << (32u - bits));
}

inline std::uint32_t Ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline std::uint32_t Maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline std::uint32_t Sigma0(std::uint32_t x) {
    return RightRotate(x, 2) ^ RightRotate(x, 13) ^ RightRotate(x, 22);
}

inline std::uint32_t Sigma1(std::uint32_t x) {
    return RightRotate(x, 6) ^ RightRotate(x, 11) ^ RightRotate(x, 25);
}

inline std::uint32_t Gamma0(std::uint32_t x) {
    return RightRotate(x, 7) ^ RightRotate(x, 18) ^ (x >> 3);
}

inline std::uint32_t Gamma1(std::uint32_t x) {
    return RightRotate(x, 17) ^ RightRotate(x, 19) ^ (x >> 10);
}

std::array<std::uint8_t, 32> Sha256Internal(const std::uint8_t *data, std::size_t len) {
    std::array<std::uint32_t, 64> message_schedule{};
    std::array<std::uint32_t, 8> hash = kInitHash;

    const std::size_t block_size = 64;
    std::size_t processed = 0;

    while (processed + block_size <= len) {
        std::memcpy(message_schedule.data(), data + processed, block_size);
        for (std::size_t i = 0; i < 16; ++i) {
            message_schedule[i] =
                (message_schedule[i] & 0x000000FFu) << 24 | (message_schedule[i] & 0x0000FF00u) << 8 |
                (message_schedule[i] & 0x00FF0000u) >> 8 | (message_schedule[i] & 0xFF000000u) >> 24;
        }
        for (std::size_t i = 16; i < 64; ++i) {
            message_schedule[i] = Gamma1(message_schedule[i - 2]) + message_schedule[i - 7] +
                                  Gamma0(message_schedule[i - 15]) + message_schedule[i - 16];
        }

        std::uint32_t a = hash[0];
        std::uint32_t b = hash[1];
        std::uint32_t c = hash[2];
        std::uint32_t d = hash[3];
        std::uint32_t e = hash[4];
        std::uint32_t f = hash[5];
        std::uint32_t g = hash[6];
        std::uint32_t h = hash[7];

        for (std::size_t i = 0; i < 64; ++i) {
            std::uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + kRoundConstants[i] + message_schedule[i];
            std::uint32_t t2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;

        processed += block_size;
    }

    std::array<std::uint8_t, 64> buffer{};
    std::size_t buffer_len = len - processed;
    std::memcpy(buffer.data(), data + processed, buffer_len);

    buffer[buffer_len++] = 0x80u;

    if (buffer_len > 56) {
        std::fill(buffer.begin() + buffer_len, buffer.end(), 0);

        message_schedule.fill(0);
        std::memcpy(message_schedule.data(), buffer.data(), block_size);
        for (std::size_t i = 0; i < 16; ++i) {
            message_schedule[i] =
                (message_schedule[i] & 0x000000FFu) << 24 | (message_schedule[i] & 0x0000FF00u) << 8 |
                (message_schedule[i] & 0x00FF0000u) >> 8 | (message_schedule[i] & 0xFF000000u) >> 24;
        }
        for (std::size_t i = 16; i < 64; ++i) {
            message_schedule[i] = Gamma1(message_schedule[i - 2]) + message_schedule[i - 7] +
                                  Gamma0(message_schedule[i - 15]) + message_schedule[i - 16];
        }

        std::uint32_t a = hash[0];
        std::uint32_t b = hash[1];
        std::uint32_t c = hash[2];
        std::uint32_t d = hash[3];
        std::uint32_t e = hash[4];
        std::uint32_t f = hash[5];
        std::uint32_t g = hash[6];
        std::uint32_t h = hash[7];

        for (std::size_t i = 0; i < 64; ++i) {
            std::uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + kRoundConstants[i] + message_schedule[i];
            std::uint32_t t2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;

        buffer.fill(0);
        buffer_len = 0;
    }

    std::fill(buffer.begin() + buffer_len, buffer.begin() + 56, 0);
    const std::uint64_t bit_len = static_cast<std::uint64_t>(len) * 8u;
    for (int i = 0; i < 8; ++i) {
        buffer[63 - i] = static_cast<std::uint8_t>((bit_len >> (8 * i)) & 0xFFu);
    }

    message_schedule.fill(0);
    std::memcpy(message_schedule.data(), buffer.data(), block_size);
    for (std::size_t i = 0; i < 16; ++i) {
        message_schedule[i] =
            (message_schedule[i] & 0x000000FFu) << 24 | (message_schedule[i] & 0x0000FF00u) << 8 |
            (message_schedule[i] & 0x00FF0000u) >> 8 | (message_schedule[i] & 0xFF000000u) >> 24;
    }
    for (std::size_t i = 16; i < 64; ++i) {
        message_schedule[i] = Gamma1(message_schedule[i - 2]) + message_schedule[i - 7] +
                              Gamma0(message_schedule[i - 15]) + message_schedule[i - 16];
    }

    std::uint32_t a = hash[0];
    std::uint32_t b = hash[1];
    std::uint32_t c = hash[2];
    std::uint32_t d = hash[3];
    std::uint32_t e = hash[4];
    std::uint32_t f = hash[5];
    std::uint32_t g = hash[6];
    std::uint32_t h = hash[7];

    for (std::size_t i = 0; i < 64; ++i) {
        std::uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + kRoundConstants[i] + message_schedule[i];
        std::uint32_t t2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;

    std::array<std::uint8_t, 32> digest{};
    for (std::size_t i = 0; i < 8; ++i) {
        digest[i * 4] = static_cast<std::uint8_t>((hash[i] >> 24) & 0xFFu);
        digest[i * 4 + 1] = static_cast<std::uint8_t>((hash[i] >> 16) & 0xFFu);
        digest[i * 4 + 2] = static_cast<std::uint8_t>((hash[i] >> 8) & 0xFFu);
        digest[i * 4 + 3] = static_cast<std::uint8_t>(hash[i] & 0xFFu);
    }

    return digest;
}

inline int HexNibble(char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    }
    if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    }
    if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

}  // namespace

std::array<std::uint8_t, 32> Sha256(const std::uint8_t *data, std::size_t len) {
    if (!data && len != 0) {
        throw std::invalid_argument("Sha256 called with null data and non-zero length");
    }
    return Sha256Internal(data ? data : reinterpret_cast<const std::uint8_t *>(""), len);
}

std::array<std::uint8_t, 32> Sha256(std::string_view data) {
    return Sha256(reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
}

std::vector<std::uint8_t> HmacSha256(const std::vector<std::uint8_t> &key,
                                     const std::uint8_t *data,
                                     std::size_t len) {
    constexpr std::size_t block_size = 64;
    std::vector<std::uint8_t> normalized_key = key;
    if (normalized_key.size() > block_size) {
        auto hashed = Sha256(normalized_key.data(), normalized_key.size());
        normalized_key.assign(hashed.begin(), hashed.end());
    }
    normalized_key.resize(block_size, 0);

    std::array<std::uint8_t, block_size> o_key_pad{};
    std::array<std::uint8_t, block_size> i_key_pad{};
    for (std::size_t i = 0; i < block_size; ++i) {
        o_key_pad[i] = normalized_key[i] ^ 0x5cu;
        i_key_pad[i] = normalized_key[i] ^ 0x36u;
    }

    std::vector<std::uint8_t> inner(block_size + len);
    std::memcpy(inner.data(), i_key_pad.data(), block_size);
    if (len > 0) {
        std::memcpy(inner.data() + block_size, data, len);
    }
    auto inner_hash = Sha256(inner.data(), inner.size());

    std::vector<std::uint8_t> outer(block_size + inner_hash.size());
    std::memcpy(outer.data(), o_key_pad.data(), block_size);
    std::memcpy(outer.data() + block_size, inner_hash.data(), inner_hash.size());

    auto result = Sha256(outer.data(), outer.size());
    return std::vector<std::uint8_t>(result.begin(), result.end());
}

std::string BytesToHex(const std::uint8_t *data, std::size_t len) {
    static const char *kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0Fu]);
        out.push_back(kHex[data[i] & 0x0Fu]);
    }
    return out;
}

std::vector<std::uint8_t> HexToBytes(std::string_view hex) {
    std::vector<std::uint8_t> result;
    int high = -1;
    for (char c : hex) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == ':' || c == '-') {
            continue;
        }
        int nibble = HexNibble(c);
        if (nibble < 0) {
            throw std::invalid_argument("HexToBytes: invalid character");
        }
        if (high < 0) {
            high = nibble;
        } else {
            result.push_back(static_cast<std::uint8_t>((high << 4) | nibble));
            high = -1;
        }
    }
    if (high >= 0) {
        throw std::invalid_argument("HexToBytes: odd number of digits");
    }
    return result;
}

}  // namespace wslmon

