cmake_minimum_required(VERSION 3.20)
project(WSL2SuddenShutdownPrevention)

add_subdirectory(shared)
if (WIN32)
    add_subdirectory(windows)
elseif (UNIX)
    add_subdirectory(ubuntu)
endif()

