#pragma once

#include <Windows.h>
#include <Evntcons.h>
#include <winevt.h>
#include <Winsvc.h>

namespace wslmon::windows {

class ScopedHandle {
  public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE handle) : handle_(handle) {}
    ~ScopedHandle() { reset(); }

    ScopedHandle(const ScopedHandle &) = delete;
    ScopedHandle &operator=(const ScopedHandle &) = delete;

    ScopedHandle(ScopedHandle &&other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    ScopedHandle &operator=(ScopedHandle &&other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    HANDLE get() const { return handle_; }
    explicit operator bool() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    HANDLE release() {
        HANDLE tmp = handle_;
        handle_ = nullptr;
        return tmp;
    }

    void reset(HANDLE handle = nullptr) {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

  private:
    HANDLE handle_ = nullptr;
};

class ScopedEvtHandle {
  public:
    ScopedEvtHandle() = default;
    explicit ScopedEvtHandle(EVT_HANDLE handle) : handle_(handle) {}
    ~ScopedEvtHandle() { reset(); }

    ScopedEvtHandle(const ScopedEvtHandle &) = delete;
    ScopedEvtHandle &operator=(const ScopedEvtHandle &) = delete;

    ScopedEvtHandle(ScopedEvtHandle &&other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    ScopedEvtHandle &operator=(ScopedEvtHandle &&other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    EVT_HANDLE get() const { return handle_; }
    explicit operator bool() const { return handle_ != nullptr; }

    EVT_HANDLE release() {
        EVT_HANDLE tmp = handle_;
        handle_ = nullptr;
        return tmp;
    }

    void reset(EVT_HANDLE handle = nullptr) {
        if (handle_) {
            EvtClose(handle_);
        }
        handle_ = handle;
    }

  private:
    EVT_HANDLE handle_ = nullptr;
};

class ScopedServiceHandle {
  public:
    ScopedServiceHandle() = default;
    explicit ScopedServiceHandle(SC_HANDLE handle) : handle_(handle) {}
    ~ScopedServiceHandle() { reset(); }

    ScopedServiceHandle(const ScopedServiceHandle &) = delete;
    ScopedServiceHandle &operator=(const ScopedServiceHandle &) = delete;

    ScopedServiceHandle(ScopedServiceHandle &&other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    ScopedServiceHandle &operator=(ScopedServiceHandle &&other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    SC_HANDLE get() const { return handle_; }
    explicit operator bool() const { return handle_ != nullptr; }

    SC_HANDLE release() {
        SC_HANDLE tmp = handle_;
        handle_ = nullptr;
        return tmp;
    }

    void reset(SC_HANDLE handle = nullptr) {
        if (handle_) {
            CloseServiceHandle(handle_);
        }
        handle_ = handle;
    }

  private:
    SC_HANDLE handle_ = nullptr;
};

}  // namespace wslmon::windows

