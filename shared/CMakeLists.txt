add_library(shared STATIC
    src/event.cpp
    src/logger.cpp)

target_include_directories(shared
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_features(shared PUBLIC cxx_std_17)

if (MSVC)
    target_compile_definitions(shared PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

