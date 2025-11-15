#include "ipc_bridge.hpp"

#include "ipc.hpp"

#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace wslmon::ubuntu {
namespace {
bool write_full(int fd, const std::uint8_t *buffer, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        ssize_t written = ::write(fd, buffer + offset, length - offset);
        if (written <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

bool read_full(int fd, std::uint8_t *buffer, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        ssize_t read_bytes = ::read(fd, buffer + offset, length - offset);
        if (read_bytes <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(read_bytes);
    }
    return true;
}

void add_attribute(EventRecord &record, const std::string &key, const std::string &value) {
    for (auto &attr : record.attributes) {
        if (attr.key == key) {
            attr.value = value;
            return;
        }
    }
    record.attributes.push_back({key, value});
}
}  // namespace

IpcBridge::IpcBridge(EventCallback callback, std::string log_origin)
    : callback_(std::move(callback)), log_origin_(std::move(log_origin)) {
    secret_path_ = kSecretInstallPath;
}

IpcBridge::~IpcBridge() { Stop(); }

void IpcBridge::Start() {
    if (running_.exchange(true)) {
        return;
    }
    load_secret();
    pipe_thread_ = std::thread(&IpcBridge::pipe_worker, this);
    unix_thread_ = std::thread(&IpcBridge::unix_worker, this);
}

void IpcBridge::Stop() {
    if (!running_.exchange(false)) {
        return;
    }
    queue_cv_.notify_all();
    if (pipe_fd_ >= 0) {
        ::close(pipe_fd_);
        pipe_fd_ = -1;
    }
    if (server_fd_ >= 0) {
        ::shutdown(server_fd_, SHUT_RDWR);
        ::close(server_fd_);
        server_fd_ = -1;
    }
    if (pipe_thread_.joinable()) {
        pipe_thread_.join();
    }
    if (unix_thread_.joinable()) {
        unix_thread_.join();
    }
}

void IpcBridge::EnqueueGuestEvent(const EventRecord &record) {
    if (!running_.load()) {
        return;
    }
    std::lock_guard<std::mutex> lock(queue_mutex_);
    outbound_.push_back(record);
    queue_cv_.notify_one();
}

bool IpcBridge::load_secret() {
    std::ifstream in(secret_path_, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }
    std::vector<std::uint8_t> secret((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (secret.empty()) {
        return false;
    }
    secret_ = std::move(secret);
    return true;
}

bool IpcBridge::connect_named_pipe(int &fd) {
    fd = ::open(kPipePath, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    return true;
}

bool IpcBridge::send_event_via_pipe(int fd,
                                    const EventRecord &record,
                                    const std::vector<std::uint8_t> &session) {
    if (session.empty()) {
        return false;
    }
    auto write_fn = [fd](const std::uint8_t *buffer, std::size_t bytes) -> bool {
        return write_full(fd, buffer, bytes);
    };
    return IpcSendEvent(write_fn, session, record);
}

void IpcBridge::pipe_worker() {
    while (running_.load()) {
        if (secret_.empty()) {
            load_secret();
            if (secret_.empty()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
        }

        int fd = -1;
        if (!connect_named_pipe(fd)) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }
        pipe_fd_ = fd;

        auto write_fn = [fd](const std::uint8_t *buffer, std::size_t bytes) -> bool {
            return write_full(fd, buffer, bytes);
        };
        auto read_fn = [fd](std::uint8_t *buffer, std::size_t bytes) -> bool {
            return read_full(fd, buffer, bytes);
        };

        std::vector<std::uint8_t> session;
        if (!IpcClientHandshake(write_fn, read_fn, secret_, session)) {
            ::close(fd);
            pipe_fd_ = -1;
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(session_mutex_);
            pipe_session_ = session;
        }

        bool reconnect = false;
        while (running_.load() && !reconnect) {
            EventRecord record;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_cv_.wait(lock, [&] { return !running_.load() || !outbound_.empty(); });
                if (!running_.load()) {
                    break;
                }
                record = outbound_.front();
                outbound_.pop_front();
            }

            std::vector<std::uint8_t> session_copy;
            {
                std::lock_guard<std::mutex> lock(session_mutex_);
                session_copy = pipe_session_;
            }
            if (!send_event_via_pipe(fd, record, session_copy)) {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                outbound_.push_front(record);
                reconnect = true;
            }
        }

        {
            std::lock_guard<std::mutex> lock(session_mutex_);
            pipe_session_.clear();
        }
        ::close(fd);
        pipe_fd_ = -1;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

void IpcBridge::unix_worker() {
    std::filesystem::path socket_path(kUnixSocketPath);
    std::filesystem::create_directories(socket_path.parent_path());
    ::unlink(kUnixSocketPath);

    server_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        return;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", kUnixSocketPath);
    if (::bind(server_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(sockaddr_un)) < 0) {
        ::close(server_fd_);
        server_fd_ = -1;
        return;
    }
    ::chmod(kUnixSocketPath, 0660);
    if (::listen(server_fd_, 1) < 0) {
        ::close(server_fd_);
        server_fd_ = -1;
        return;
    }

    while (running_.load()) {
        int client = ::accept(server_fd_, nullptr, nullptr);
        if (client < 0) {
            if (running_.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            continue;
        }

        if (secret_.empty()) {
            load_secret();
        }
        if (secret_.empty()) {
            ::close(client);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        auto write_fn = [client](const std::uint8_t *buffer, std::size_t bytes) -> bool {
            return write_full(client, buffer, bytes);
        };
        auto read_fn = [client](std::uint8_t *buffer, std::size_t bytes) -> bool {
            return read_full(client, buffer, bytes);
        };

        std::vector<std::uint8_t> session;
        if (!IpcServerHandshake(write_fn, read_fn, secret_, session)) {
            ::close(client);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        while (running_.load()) {
            EventRecord record;
            if (!IpcReceiveEvent(read_fn, session, record)) {
                break;
            }
            add_attribute(record, "peer_origin", log_origin_);
            callback_(std::move(record));
        }

        ::close(client);
    }

    ::close(server_fd_);
    server_fd_ = -1;
    ::unlink(kUnixSocketPath);
}

}  // namespace wslmon::ubuntu

