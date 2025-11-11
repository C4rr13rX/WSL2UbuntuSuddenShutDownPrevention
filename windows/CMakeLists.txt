cmake_minimum_required(VERSION 3.20)
project(WslShutdownMonitor LANGUAGES CXX)

if (NOT TARGET shared)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../shared ${CMAKE_CURRENT_BINARY_DIR}/shared)
endif()

add_executable(WslShutdownMonitor
    src/main.cpp
    src/windows_service.cpp
    src/event_collector.cpp
    src/event_log_collector.cpp
    src/power_collector.cpp
    src/process_collector.cpp
    src/security_collector.cpp
    src/service_health_collector.cpp
    src/wsl_diagnostic_collector.cpp
    src/wer_collector.cpp)

target_include_directories(WslShutdownMonitor
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../shared/include)

target_link_libraries(WslShutdownMonitor PRIVATE shared Wtsapi32.lib PowrProf.lib wbemuuid.lib wevtapi.lib Advapi32.lib Psapi.lib)

target_compile_definitions(WslShutdownMonitor PRIVATE UNICODE _UNICODE)

target_compile_features(WslShutdownMonitor PRIVATE cxx_std_17)

