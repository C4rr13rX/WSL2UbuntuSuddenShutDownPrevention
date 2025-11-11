cmake_minimum_required(VERSION 3.20)
project(WSL2SuddenShutdownPrevention)

enable_testing()
add_subdirectory(shared)
add_subdirectory(tools)
if (WIN32)
    add_subdirectory(windows)
elseif (UNIX)
    add_subdirectory(ubuntu)
endif()

add_subdirectory(tests)

