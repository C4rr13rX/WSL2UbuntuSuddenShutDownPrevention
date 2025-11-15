#include "security_collector.hpp"

#include <Windows.h>
#include <Wbemidl.h>
#include <comdef.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

bool contains_case_insensitive(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) ==
                                                    std::tolower(static_cast<unsigned char>(b)); });
    return it != haystack.end();
}

std::string service_state_to_text(DWORD state) {
    switch (state) {
        case SERVICE_STOPPED:
            return "Stopped";
        case SERVICE_START_PENDING:
            return "StartPending";
        case SERVICE_STOP_PENDING:
            return "StopPending";
        case SERVICE_RUNNING:
            return "Running";
        case SERVICE_CONTINUE_PENDING:
            return "ContinuePending";
        case SERVICE_PAUSE_PENDING:
            return "PausePending";
        case SERVICE_PAUSED:
            return "Paused";
        default:
            return "Unknown";
    }
}

struct VendorProbe {
    std::wstring service_name;
    std::string vendor_fragment;
    std::string component;
};

template <typename EmitFn>
void emit_vendor_service_state(EmitFn &&emit_fn,
                               ShutdownMonitorService &service,
                               const VendorProbe &probe,
                               const std::string &vendor_name,
                               const std::string &suite) {
    if (!contains_case_insensitive(vendor_name, probe.vendor_fragment)) {
        return;
    }
    ScopedServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        return;
    }
    ScopedServiceHandle vendor_service(
        OpenServiceW(scm.get(), probe.service_name.c_str(), SERVICE_QUERY_STATUS));

    EventRecord record;
    record.category = "Security";
    record.attributes.push_back({"vendor", vendor_name});
    record.attributes.push_back({"suite", suite});
    record.attributes.push_back({"probe", probe.component});
    record.attributes.push_back({"service", bstr_to_utf8(_bstr_t(probe.service_name.c_str()))});

    if (!vendor_service) {
        record.severity = "Warning";
        record.message = "Vendor service unavailable";
        record.attributes.push_back({"error", std::to_string(GetLastError())});
        emit_fn(std::move(record));
        return;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(vendor_service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status),
                              sizeof(status), &bytes_needed)) {
        record.severity = "Warning";
        record.message = "Vendor service state query failed";
        record.attributes.push_back({"error", std::to_string(GetLastError())});
        emit_fn(std::move(record));
        return;
    }

    record.severity = status.dwCurrentState == SERVICE_RUNNING ? "Info" : "Warning";
    record.message = "Vendor service state";
    record.attributes.push_back({"serviceState", service_state_to_text(status.dwCurrentState)});
    record.attributes.push_back({"pid", std::to_string(status.dwProcessId)});
    emit_fn(std::move(record));
}
}  // namespace

namespace {
const std::array<VendorProbe, 5> kVendorProbes = {{{L"SepMasterService", "symantec", "Symantec Endpoint"},
                                                   {L"mfemms", "mcafee", "McAfee Endpoint"},
                                                   {L"CSFalconService", "crowdstrike", "CrowdStrike Sensor"},
                                                   {L"SentinelAgent", "sentinel", "SentinelOne Agent"},
                                                   {L"ossecsvc", "trend", "TrendMicro/OSSEC"}}};
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
                          reinterpret_cast<void **>(locator_.GetAddressOf()));
    if (FAILED(hr)) {
        return false;
    }
    hr = locator_->ConnectServer(_bstr_t(L"ROOT\\SecurityCenter2"), nullptr, nullptr, nullptr, 0, nullptr, nullptr,
                                 services_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = CoSetProxyBlanket(services_.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        return false;
    }
    return true;
}

void SecurityCollector::Start(ShutdownMonitorService &service) {
    if (!initialize_wmi()) {
        EventRecord record;
        record.category = "Security";
        record.severity = "Error";
        record.message = "Failed to initialize WMI security collector";
        emit(service, std::move(record));
        if (com_initialized_) {
            CoUninitialize();
            com_initialized_ = false;
        }
        return;
    }
    stop_event_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop_event_) {
        EventRecord record;
        record.category = "Security";
        record.severity = "Error";
        record.message = "Failed to create stop event for security collector";
        emit(service, std::move(record));
        return;
    }

    auto ctx = std::make_unique<std::pair<SecurityCollector *, ShutdownMonitorService *>>(this, &service);
    HANDLE thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto *ctx_ptr = static_cast<std::pair<SecurityCollector *, ShutdownMonitorService *> *>(param);
        std::unique_ptr<std::pair<SecurityCollector *, ShutdownMonitorService *>> holder(ctx_ptr);
        holder->first->run(*holder->second);
        return 0;
    }, ctx.get(), 0, nullptr);
    if (!thread) {
        EventRecord record;
        record.category = "Security";
        record.severity = "Error";
        record.message = "Failed to create security collector thread";
        emit(service, std::move(record));
        return;
    }
    thread_handle_.reset(thread);
    ctx.release();
}

void SecurityCollector::Stop() {
    if (stop_event_) {
        SetEvent(stop_event_.get());
    }
    if (thread_handle_) {
        WaitForSingleObject(thread_handle_.get(), INFINITE);
    }
    thread_handle_.reset();
    stop_event_.reset();
    services_.Reset();
    locator_.Reset();
    if (com_initialized_) {
        CoUninitialize();
        com_initialized_ = false;
    }
}

void SecurityCollector::run(ShutdownMonitorService &service) {
    const auto enumerate_products = [&](const wchar_t *wmi_class, const char *suite) {
        Microsoft::WRL::ComPtr<IEnumWbemClassObject> enumerator;
        std::wstring query = L"SELECT displayName, productState, pathToSignedProductExe, pathToSignedReportingExe, instanceGuid "
                             L"FROM ";
        query += wmi_class;

        HRESULT hr = services_->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
                                          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                          nullptr, enumerator.GetAddressOf());
        if (FAILED(hr)) {
            EventRecord record;
            record.category = "Security";
            record.severity = "Warning";
            record.message = "Security product query failed";
            record.attributes.push_back({"suite", suite});
            record.attributes.push_back({"error", std::to_string(hr)});
            emit(service, std::move(record));
            return;
        }

        while (true) {
            Microsoft::WRL::ComPtr<IWbemClassObject> obj;
            ULONG returned = 0;
            if (enumerator->Next(WBEM_INFINITE, 1, obj.GetAddressOf(), &returned) != S_OK || returned == 0) {
                break;
            }

            VARIANT display_name{};
            VARIANT product_state{};
            VARIANT signed_product{};
            VARIANT signed_reporting{};
            VARIANT instance_guid{};

            obj->Get(L"displayName", 0, &display_name, nullptr, nullptr);
            obj->Get(L"productState", 0, &product_state, nullptr, nullptr);
            obj->Get(L"pathToSignedProductExe", 0, &signed_product, nullptr, nullptr);
            obj->Get(L"pathToSignedReportingExe", 0, &signed_reporting, nullptr, nullptr);
            obj->Get(L"instanceGuid", 0, &instance_guid, nullptr, nullptr);

            EventRecord record;
            record.category = "Security";
            record.message = "Security product state";
            record.attributes.push_back({"suite", suite});
            std::string vendor_name = bstr_to_utf8(display_name.bstrVal);
            record.attributes.push_back({"name", vendor_name});
            if (signed_product.vt == VT_BSTR) {
                record.attributes.push_back({"productExe", bstr_to_utf8(signed_product.bstrVal)});
            }
            if (signed_reporting.vt == VT_BSTR) {
                record.attributes.push_back({"reportingExe", bstr_to_utf8(signed_reporting.bstrVal)});
            }
            if (instance_guid.vt == VT_BSTR) {
                record.attributes.push_back({"instanceGuid", bstr_to_utf8(instance_guid.bstrVal)});
            }

            std::string state_text;
            if (product_state.vt == VT_I4) {
                state_text = product_state_to_text(product_state.lVal);
                record.attributes.push_back({"productState", std::to_string(product_state.lVal)});
                record.attributes.push_back({"stateText", state_text});
            }

            record.severity = "Info";
            if (!state_text.empty() && contains_case_insensitive(state_text, "Disabled")) {
                record.severity = "Warning";
            } else if (!state_text.empty() && contains_case_insensitive(state_text, "Outdated")) {
                record.severity = "Warning";
            }

            emit(service, std::move(record));

            auto emit_fn = [&](EventRecord evt) { emit(service, std::move(evt)); };
            for (const auto &probe : kVendorProbes) {
                emit_vendor_service_state(emit_fn, service, probe, vendor_name, suite);
            }

            VariantClear(&display_name);
            VariantClear(&product_state);
            VariantClear(&signed_product);
            VariantClear(&signed_reporting);
            VariantClear(&instance_guid);
        }
    };

    while (WaitForSingleObject(stop_event_.get(), 10000) == WAIT_TIMEOUT) {
        enumerate_products(L"AntiVirusProduct", "ThirdPartyAV");
        enumerate_products(L"AntiSpywareProduct", "ThirdPartyAS");
        enumerate_products(L"FirewallProduct", "ThirdPartyFW");
    }
}

}  // namespace wslmon::windows

