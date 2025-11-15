cmake_minimum_required(VERSION 3.20)

add_executable(master_report
    main.cpp)

target_include_directories(master_report
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/include)

target_link_libraries(master_report PRIVATE shared)

target_compile_features(master_report PRIVATE cxx_std_17)

if (MSVC)
    target_compile_definitions(master_report PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
