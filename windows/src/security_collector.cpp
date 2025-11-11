#include "security_collector.hpp"

#include <Windows.h>
#include <Wbemidl.h>
#include <comdef.h>

#include <string>
#include <utility>

#include "windows_service.hpp"

#pragma comment(lib, "wbemuuid.lib")

namespace wslmon::windows {

namespace {
std::string bstr_to_utf8(BSTR bstr) {
    if (!bstr) {
        return {};
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, bstr, SysStringLen(bstr), nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, bstr, SysStringLen(bstr), result.data(), size_needed, nullptr, nullptr);
    return result;
}

std::string product_state_to_text(DWORD state) {
    constexpr DWORD kEnabledMask = 0x10;
    constexpr DWORD kUpToDateMask = 0x1000;
    bool enabled = (state & kEnabledMask) != 0;
    bool up_to_date = (state & kUpToDateMask) != 0;
    return std::string(enabled ? "Enabled" : "Disabled") + (up_to_date ? "|UpToDate" : "|Outdated");
}
}

SecurityCollector::SecurityCollector() : EventCollector(L"Security") {}

bool SecurityCollector::initialize_wmi() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        com_initialized_ = true;
    } else if (hr != RPC_E_CHANGED_MODE) {
        return false;
    }
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        return false;
    }
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                          reinterpret_cast<void **>(&locator_));
    if (FAILED(hr)) {
        return false;
    }
    hr = locator_->ConnectServer(_bstr_t(L"ROOT\\SecurityCenter2"), nullptr, nullptr, nullptr, 0, nullptr, nullptr,
                                 &services_);
    if (FAILED(hr)) {
        return false;
    }
    hr = CoSetProxyBlanket(services_, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        return false;
    }
    return true;
}

void SecurityCollector::cleanup_wmi() {
    if (services_) {
        services_->Release();
        services_ = nullptr;
    }
    if (locator_) {
        locator_->Release();
        locator_ = nullptr;
    }
    if (com_initialized_) {
        CoUninitialize();
        com_initialized_ = false;
    }
}

void SecurityCollector::Start(ShutdownMonitorService &service) {
    if (!initialize_wmi()) {
        EventRecord record;
        record.category = "Security";
        record.severity = "Error";
        record.message = "Failed to initialize WMI security collector";
        emit(service, std::move(record));
        cleanup_wmi();
        return;
    }
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    auto *ctx = new std::pair<SecurityCollector *, ShutdownMonitorService *>(this, &service);
    thread_handle_ = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto *ctx = static_cast<std::pair<SecurityCollector *, ShutdownMonitorService *> *>(param);
        ctx->first->run(*ctx->second);
        delete ctx;
        return 0;
    }, ctx, 0, nullptr);
    if (!thread_handle_) {
        delete ctx;
        EventRecord record;
        record.category = "Security";
        record.severity = "Error";
        record.message = "Failed to create security collector thread";
        emit(service, std::move(record));
    }
}

void SecurityCollector::Stop() {
    if (stop_event_) {
        SetEvent(stop_event_);
    }
    if (thread_handle_) {
        WaitForSingleObject(thread_handle_, INFINITE);
        CloseHandle(thread_handle_);
        thread_handle_ = nullptr;
    }
    if (stop_event_) {
        CloseHandle(stop_event_);
        stop_event_ = nullptr;
    }
    cleanup_wmi();
}

void SecurityCollector::run(ShutdownMonitorService &service) {
    while (WaitForSingleObject(stop_event_, 10000) == WAIT_TIMEOUT) {
        IEnumWbemClassObject *enumerator = nullptr;
        HRESULT hr = services_->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT displayName, productState FROM AntiVirusProduct"),
                                          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator);
        if (FAILED(hr)) {
            EventRecord record;
            record.category = "Security";
            record.severity = "Warning";
            record.message = "AntiVirusProduct query failed";
            record.attributes.push_back({"error", std::to_string(hr)});
            emit(service, std::move(record));
            continue;
        }
        IWbemClassObject *obj = nullptr;
        ULONG returned = 0;
        while (enumerator->Next(WBEM_INFINITE, 1, &obj, &returned) == S_OK) {
            VARIANT display_name{};
            VARIANT product_state{};
            obj->Get(L"displayName", 0, &display_name, nullptr, nullptr);
            obj->Get(L"productState", 0, &product_state, nullptr, nullptr);

            EventRecord record;
            record.category = "Security";
            record.severity = "Info";
            record.message = "Security product state";
            record.attributes.push_back({"name", bstr_to_utf8(display_name.bstrVal)});
            if (product_state.vt == VT_I4) {
                record.attributes.push_back({"productState", std::to_string(product_state.lVal)});
                record.attributes.push_back({"stateText", product_state_to_text(product_state.lVal)});
            }
            emit(service, std::move(record));

            VariantClear(&display_name);
            VariantClear(&product_state);
            obj->Release();
        }
        if (enumerator) {
            enumerator->Release();
        }
    }
}

}  // namespace wslmon::windows

