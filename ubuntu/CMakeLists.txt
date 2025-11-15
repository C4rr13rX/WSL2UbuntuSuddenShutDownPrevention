cmake_minimum_required(VERSION 3.16)
project(wsl_monitor LANGUAGES CXX)

if (NOT TARGET shared)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../shared ${CMAKE_CURRENT_BINARY_DIR}/shared)
endif()

add_executable(wsl_monitor
    src/main.cpp
    src/monitor_daemon.cpp
    src/ipc_bridge.cpp)

target_include_directories(wsl_monitor
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../shared/include)

target_link_libraries(wsl_monitor PRIVATE shared systemd)

target_compile_features(wsl_monitor PRIVATE cxx_std_20)

install(TARGETS wsl_monitor DESTINATION bin)

