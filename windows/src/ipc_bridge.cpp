#include "ipc_bridge.hpp"

#include "ipc.hpp"
#include "windows_service.hpp"

#include "logger.hpp"
#include "ring_buffer.hpp"

#include <afunix.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <thread>

#pragma comment(lib, "Ws2_32.lib")

namespace wslmon::windows {
namespace {
constexpr wchar_t kProgramDataRoot[] = L"C:/ProgramData/WslMonitor";
constexpr wchar_t kSecretFile[] = L"C:/ProgramData/WslMonitor/ipc.key";
constexpr wchar_t kConfigFile[] = L"C:/ProgramData/WslMonitor/ipc.config";
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\WslMonitorBridge";

bool write_full(HANDLE pipe, const std::uint8_t *buffer, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD written = 0;
        if (!::WriteFile(pipe, buffer + offset, static_cast<DWORD>(length - offset), &written, nullptr)) {
            return false;
        }
        if (written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}

bool read_full(HANDLE pipe, std::uint8_t *buffer, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        DWORD read_bytes = 0;
        if (!::ReadFile(pipe, buffer + offset, static_cast<DWORD>(length - offset), &read_bytes, nullptr)) {
            return false;
        }
        if (read_bytes == 0) {
            return false;
        }
        offset += read_bytes;
    }
    return true;
}

bool write_full_socket(SOCKET socket, const std::uint8_t *buffer, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        int sent = ::send(socket, reinterpret_cast<const char *>(buffer + offset), static_cast<int>(length - offset), 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            return false;
        }
        offset += static_cast<std::size_t>(sent);
    }
    return true;
}

bool read_full_socket(SOCKET socket, std::uint8_t *buffer, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        int received = ::recv(socket, reinterpret_cast<char *>(buffer + offset), static_cast<int>(length - offset), 0);
        if (received == SOCKET_ERROR || received == 0) {
            return false;
        }
        offset += static_cast<std::size_t>(received);
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

std::string build_unix_path(const std::string &distro, const std::string &socket_path) {
    std::string normalized = socket_path;
    if (!normalized.empty() && normalized.front() == '/') {
        normalized.erase(normalized.begin());
    }
    for (auto &ch : normalized) {
        if (ch == '/') {
            ch = '\\';
        }
    }
    std::string result = "\\\\?\\pipe\\wsl\\" + distro;
    if (!normalized.empty()) {
        result += '\\' + normalized;
    }
    return result;
}

void log_error(ShutdownMonitorService &service, const std::string &message) {
    EventRecord record;
    record.category = "IPC";
    record.severity = "Warning";
    record.message = message;
    service.Logger().Append(record);
}

}  // namespace

IpcBridge::IpcBridge(ShutdownMonitorService &service) : service_(service) {
    ensure_program_data();
}

IpcBridge::~IpcBridge() { Stop(); }

bool IpcBridge::ensure_program_data() {
    std::filesystem::create_directories(std::filesystem::path(kProgramDataRoot));
    secret_path_ = kSecretFile;
    config_path_ = kConfigFile;
    return true;
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

bool IpcBridge::load_config() {
    std::ifstream in(config_path_);
    if (!in.is_open()) {
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        if (key == "distro") {
            distro_name_ = value;
        } else if (key == "socket") {
            socket_path_ = value;
        }
    }
    if (distro_name_.empty()) {
        distro_name_ = "Ubuntu";
    }
    if (socket_path_.empty()) {
        socket_path_ = "/var/run/wsl-monitor/host.sock";
    }
    return true;
}

void IpcBridge::Start() {
    if (running_.exchange(true)) {
        return;
    }
    if (!load_secret()) {
        log_error(service_, "Failed to load IPC secret key; retrying in background");
    }
    if (!load_config()) {
        log_error(service_, "Failed to load IPC configuration; using defaults");
    }
    pipe_thread_ = std::thread(&IpcBridge::pipe_worker, this);
    unix_thread_ = std::thread(&IpcBridge::unix_worker, this);
}

void IpcBridge::Stop() {
    if (!running_.exchange(false)) {
        return;
    }
    queue_cv_.notify_all();
    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
        ::CancelIoEx(pipe_handle_, nullptr);
        ::CloseHandle(pipe_handle_);
        pipe_handle_ = INVALID_HANDLE_VALUE;
    }
    if (socket_handle_ != INVALID_SOCKET) {
        ::shutdown(socket_handle_, SD_BOTH);
        ::closesocket(socket_handle_);
        socket_handle_ = INVALID_SOCKET;
    }
    if (pipe_thread_.joinable()) {
        pipe_thread_.join();
    }
    if (unix_thread_.joinable()) {
        unix_thread_.join();
    }
}

void IpcBridge::EnqueueHostEvent(const EventRecord &record) {
    if (!running_.load()) {
        return;
    }
    std::lock_guard<std::mutex> lock(queue_mutex_);
    outbound_.push_back(record);
    queue_cv_.notify_one();
}

void IpcBridge::handle_guest_event(EventRecord record) {
    add_attribute(record, "peer_origin", "guest");
    service_.Buffer().Push(record);
    service_.Logger().Append(record);
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

        HANDLE pipe = ::CreateNamedPipeW(kPipeName,
                                         PIPE_ACCESS_DUPLEX,
                                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                         1,
                                         64 * 1024,
                                         64 * 1024,
                                         0,
                                         nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }
        pipe_handle_ = pipe;

        BOOL connected = ::ConnectNamedPipe(pipe, nullptr) ? TRUE : FALSE;
        if (!connected) {
            DWORD error = GetLastError();
            if (error != ERROR_PIPE_CONNECTED) {
                ::CloseHandle(pipe);
                pipe_handle_ = INVALID_HANDLE_VALUE;
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
        }

        auto write_fn = [pipe](const std::uint8_t *buffer, std::size_t bytes) -> bool {
            return write_full(pipe, buffer, bytes);
        };
        auto read_fn = [pipe](std::uint8_t *buffer, std::size_t bytes) -> bool {
            return read_full(pipe, buffer, bytes);
        };

        std::vector<std::uint8_t> session;
        if (!IpcServerHandshake(write_fn, read_fn, secret_, session)) {
            ::DisconnectNamedPipe(pipe);
            ::CloseHandle(pipe);
            pipe_handle_ = INVALID_HANDLE_VALUE;
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }
        pipe_session_ = session;

        while (running_.load()) {
            EventRecord record;
            if (!IpcReceiveEvent(read_fn, pipe_session_, record)) {
                break;
            }
            handle_guest_event(std::move(record));
        }

        pipe_session_.clear();
        ::DisconnectNamedPipe(pipe);
        ::CloseHandle(pipe);
        pipe_handle_ = INVALID_HANDLE_VALUE;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

bool IpcBridge::send_event_over_socket(const EventRecord &record) {
    SOCKET socket = INVALID_SOCKET;
    std::vector<std::uint8_t> session;
    {
        std::lock_guard<std::mutex> lock(socket_mutex_);
        socket = socket_handle_;
        session = socket_session_;
    }
    if (socket == INVALID_SOCKET || session.empty()) {
        return false;
    }
    auto write_fn = [socket](const std::uint8_t *buffer, std::size_t bytes) -> bool {
        return write_full_socket(socket, buffer, bytes);
    };
    return IpcSendEvent(write_fn, session, record);
}

void IpcBridge::unix_worker() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log_error(service_, "WSAStartup failed for IPC bridge");
        return;
    }

    while (running_.load()) {
        if (secret_.empty()) {
            load_secret();
            if (secret_.empty()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
        }

        SOCKET socket = ::WSASocketW(AF_UNIX, SOCK_STREAM, 0, nullptr, 0, 0);
        if (socket == INVALID_SOCKET) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        std::string unix_path = build_unix_path(distro_name_, socket_path_);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (unix_path.size() >= sizeof(addr.sun_path)) {
            ::closesocket(socket);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        std::memcpy(addr.sun_path, unix_path.c_str(), unix_path.size() + 1);

        if (::connect(socket, reinterpret_cast<sockaddr *>(&addr), sizeof(sa_family_t) + static_cast<int>(unix_path.size()) + 1) == SOCKET_ERROR) {
            ::closesocket(socket);
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }

        auto write_fn = [socket](const std::uint8_t *buffer, std::size_t bytes) -> bool {
            return write_full_socket(socket, buffer, bytes);
        };
        auto read_fn = [socket](std::uint8_t *buffer, std::size_t bytes) -> bool {
            return read_full_socket(socket, buffer, bytes);
        };

        std::vector<std::uint8_t> session;
        if (!IpcClientHandshake(write_fn, read_fn, secret_, session)) {
            ::closesocket(socket);
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(socket_mutex_);
            socket_handle_ = socket;
            socket_session_ = session;
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
            if (!send_event_over_socket(record)) {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                outbound_.push_front(record);
                reconnect = true;
            }
        }

        {
            std::lock_guard<std::mutex> lock(socket_mutex_);
            socket_session_.clear();
            socket_handle_ = INVALID_SOCKET;
        }
        ::closesocket(socket);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    WSACleanup();
}

}  // namespace wslmon::windows

