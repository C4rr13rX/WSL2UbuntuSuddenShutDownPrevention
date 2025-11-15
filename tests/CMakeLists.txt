add_executable(heuristic_analyzer_test
    heuristic_analyzer_test.cpp)

target_link_libraries(heuristic_analyzer_test PRIVATE shared)

target_compile_features(heuristic_analyzer_test PRIVATE cxx_std_17)

add_test(NAME heuristic_analyzer_test COMMAND heuristic_analyzer_test)
