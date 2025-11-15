#include "windows_service.hpp"

#include <Windows.h>

namespace wslmon::windows {

}  // namespace wslmon::windows

int wmain() {
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(L"WslShutdownMonitor"), wslmon::windows::ServiceMain},
        {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        return GetLastError();
    }
    return 0;
}

