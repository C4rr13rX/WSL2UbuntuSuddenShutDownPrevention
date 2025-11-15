#include "ipc.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <random>
#include <vector>

#include "crypto.hpp"

namespace wslmon {
namespace {
constexpr std::array<char, 4> kServerHelloMagic{'W', 'S', 'L', 'H'};
constexpr std::array<char, 4> kClientHelloMagic{'W', 'S', 'L', 'C'};
constexpr std::array<char, 4> kServerAckMagic{'W', 'S', 'L', 'A'};
constexpr std::array<char, 4> kFrameMagic{'W', 'S', 'L', 'E'};
constexpr std::uint8_t kProtocolVersion = 1;

std::vector<std::uint8_t> HmacLabel(const std::vector<std::uint8_t> &secret,
                                    std::string_view label,
                                    const std::uint8_t *first,
                                    std::size_t first_len,
                                    const std::uint8_t *second,
                                    std::size_t second_len) {
    std::vector<std::uint8_t> input;
    input.reserve(label.size() + first_len + second_len);
    input.insert(input.end(), label.begin(), label.end());
    input.insert(input.end(), first, first + first_len);
    input.insert(input.end(), second, second + second_len);
    return HmacSha256(secret, input.data(), input.size());
}

bool ReadExact(const IpcReadFn &read_fn, std::uint8_t *buffer, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        if (!read_fn(buffer + offset, length - offset)) {
            return false;
        }
        offset = length;  // read_fn implementations are expected to read fully or fail.
    }
    return true;
}

bool WriteExact(const IpcWriteFn &write_fn, const std::uint8_t *buffer, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        if (!write_fn(buffer + offset, length - offset)) {
            return false;
        }
        offset = length;
    }
    return true;
}

bool DeserializeEventPayload(std::string_view payload, EventRecord &out_record) {
    return DeserializeEvent(payload, out_record);
}

}  // namespace

std::array<std::uint8_t, 32> GenerateNonce() {
    std::array<std::uint8_t, 32> nonce{};
    std::random_device rd;
    for (auto &byte : nonce) {
        byte = static_cast<std::uint8_t>(rd());
    }
    return nonce;
}

bool IpcServerHandshake(const IpcWriteFn &write_fn,
                        const IpcReadFn &read_fn,
                        const std::vector<std::uint8_t> &shared_secret,
                        std::vector<std::uint8_t> &session_key) {
    auto server_nonce = GenerateNonce();
    std::array<std::uint8_t, 4 + 1 + 3 + 32> server_hello{};
    std::copy(kServerHelloMagic.begin(), kServerHelloMagic.end(), server_hello.begin());
    server_hello[4] = kProtocolVersion;
    std::fill(server_hello.begin() + 5, server_hello.begin() + 8, 0);
    std::copy(server_nonce.begin(), server_nonce.end(), server_hello.begin() + 8);
    if (!WriteExact(write_fn, server_hello.data(), server_hello.size())) {
        return false;
    }

    std::array<std::uint8_t, 4 + 1 + 3 + 32 + 32> client_response{};
    if (!ReadExact(read_fn, client_response.data(), client_response.size())) {
        return false;
    }
    if (!std::equal(kClientHelloMagic.begin(), kClientHelloMagic.end(), client_response.begin())) {
        return false;
    }
    if (client_response[4] != kProtocolVersion) {
        return false;
    }
    std::array<std::uint8_t, 32> client_nonce{};
    std::copy(client_response.begin() + 8, client_response.begin() + 40, client_nonce.begin());
    std::array<std::uint8_t, 32> client_proof{};
    std::copy(client_response.begin() + 40, client_response.end(), client_proof.begin());

    const auto expected_client_proof = HmacLabel(shared_secret, "client-proof",
                                                 server_nonce.data(), server_nonce.size(),
                                                 client_nonce.data(), client_nonce.size());
    if (!std::equal(expected_client_proof.begin(), expected_client_proof.end(), client_proof.begin())) {
        return false;
    }

    const auto server_proof = HmacLabel(shared_secret, "server-proof",
                                        client_nonce.data(), client_nonce.size(),
                                        server_nonce.data(), server_nonce.size());

    std::array<std::uint8_t, 4 + 1 + 3 + 32> server_ack{};
    std::copy(kServerAckMagic.begin(), kServerAckMagic.end(), server_ack.begin());
    server_ack[4] = kProtocolVersion;
    std::fill(server_ack.begin() + 5, server_ack.begin() + 8, 0);
    std::copy(server_proof.begin(), server_proof.end(), server_ack.begin() + 8);
    if (!WriteExact(write_fn, server_ack.data(), server_ack.size())) {
        return false;
    }

    const auto session = HmacLabel(shared_secret, "session",
                                   server_nonce.data(), server_nonce.size(),
                                   client_nonce.data(), client_nonce.size());
    session_key.assign(session.begin(), session.end());
    return true;
}

bool IpcClientHandshake(const IpcWriteFn &write_fn,
                        const IpcReadFn &read_fn,
                        const std::vector<std::uint8_t> &shared_secret,
                        std::vector<std::uint8_t> &session_key) {
    std::array<std::uint8_t, 4 + 1 + 3 + 32> server_hello{};
    if (!ReadExact(read_fn, server_hello.data(), server_hello.size())) {
        return false;
    }
    if (!std::equal(kServerHelloMagic.begin(), kServerHelloMagic.end(), server_hello.begin())) {
        return false;
    }
    if (server_hello[4] != kProtocolVersion) {
        return false;
    }
    std::array<std::uint8_t, 32> server_nonce{};
    std::copy(server_hello.begin() + 8, server_hello.end(), server_nonce.begin());

    auto client_nonce = GenerateNonce();
    const auto client_proof = HmacLabel(shared_secret, "client-proof",
                                        server_nonce.data(), server_nonce.size(),
                                        client_nonce.data(), client_nonce.size());

    std::array<std::uint8_t, 4 + 1 + 3 + 32 + 32> response{};
    std::copy(kClientHelloMagic.begin(), kClientHelloMagic.end(), response.begin());
    response[4] = kProtocolVersion;
    std::fill(response.begin() + 5, response.begin() + 8, 0);
    std::copy(client_nonce.begin(), client_nonce.end(), response.begin() + 8);
    std::copy(client_proof.begin(), client_proof.end(), response.begin() + 40);
    if (!WriteExact(write_fn, response.data(), response.size())) {
        return false;
    }

    std::array<std::uint8_t, 4 + 1 + 3 + 32> server_ack{};
    if (!ReadExact(read_fn, server_ack.data(), server_ack.size())) {
        return false;
    }
    if (!std::equal(kServerAckMagic.begin(), kServerAckMagic.end(), server_ack.begin())) {
        return false;
    }
    if (server_ack[4] != kProtocolVersion) {
        return false;
    }

    std::array<std::uint8_t, 32> server_proof{};
    std::copy(server_ack.begin() + 8, server_ack.end(), server_proof.begin());
    const auto expected_server_proof = HmacLabel(shared_secret, "server-proof",
                                                 client_nonce.data(), client_nonce.size(),
                                                 server_nonce.data(), server_nonce.size());
    if (!std::equal(expected_server_proof.begin(), expected_server_proof.end(), server_proof.begin())) {
        return false;
    }

    const auto session = HmacLabel(shared_secret, "session",
                                   server_nonce.data(), server_nonce.size(),
                                   client_nonce.data(), client_nonce.size());
    session_key.assign(session.begin(), session.end());
    return true;
}

bool IpcSendEvent(const IpcWriteFn &write_fn,
                  const std::vector<std::uint8_t> &session_key,
                  const EventRecord &record) {
    if (session_key.empty()) {
        return false;
    }
    const std::string payload = SerializeEvent(record);
    const auto mac = HmacSha256(session_key, reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());

    std::uint32_t payload_len = static_cast<std::uint32_t>(payload.size());
    std::array<std::uint8_t, 4 + 1 + 1 + 2 + 4> header{};
    std::copy(kFrameMagic.begin(), kFrameMagic.end(), header.begin());
    header[4] = kProtocolVersion;
    header[5] = 1;  // event frame
    header[6] = 0;
    header[7] = 0;
    header[8] = static_cast<std::uint8_t>(payload_len & 0xFFu);
    header[9] = static_cast<std::uint8_t>((payload_len >> 8) & 0xFFu);
    header[10] = static_cast<std::uint8_t>((payload_len >> 16) & 0xFFu);
    header[11] = static_cast<std::uint8_t>((payload_len >> 24) & 0xFFu);

    if (!WriteExact(write_fn, header.data(), header.size())) {
        return false;
    }
    if (!WriteExact(write_fn, mac.data(), mac.size())) {
        return false;
    }
    return WriteExact(write_fn, reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());
}

bool IpcReceiveEvent(const IpcReadFn &read_fn,
                     const std::vector<std::uint8_t> &session_key,
                     EventRecord &out_record) {
    if (session_key.empty()) {
        return false;
    }
    std::array<std::uint8_t, 4 + 1 + 1 + 2 + 4> header{};
    if (!ReadExact(read_fn, header.data(), header.size())) {
        return false;
    }
    if (!std::equal(kFrameMagic.begin(), kFrameMagic.end(), header.begin())) {
        return false;
    }
    if (header[4] != kProtocolVersion || header[5] != 1) {
        return false;
    }
    std::uint32_t payload_len = header[8] | (header[9] << 8) | (header[10] << 16) | (header[11] << 24);

    std::array<std::uint8_t, 32> mac{};
    if (!ReadExact(read_fn, mac.data(), mac.size())) {
        return false;
    }

    std::string payload(payload_len, '\0');
    if (payload_len > 0) {
        if (!ReadExact(read_fn, reinterpret_cast<std::uint8_t *>(payload.data()), payload.size())) {
            return false;
        }
    }

    const auto expected_mac = HmacSha256(session_key,
                                         reinterpret_cast<const std::uint8_t *>(payload.data()),
                                         payload.size());
    if (!std::equal(expected_mac.begin(), expected_mac.end(), mac.begin())) {
        return false;
    }

    if (!DeserializeEventPayload(payload, out_record)) {
        return false;
    }
    return true;
}

}  // namespace wslmon

