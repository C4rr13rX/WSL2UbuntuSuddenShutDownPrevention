#include "monitor_daemon.hpp"

#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

namespace {
volatile std::sig_atomic_t g_should_stop = 0;

void handle_signal(int) { g_should_stop = 1; }
}

int main() {
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGINT, handle_signal);

    wslmon::ubuntu::MonitorDaemon daemon;
    daemon.Run();

    while (!g_should_stop) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    daemon.Stop();
    return 0;
}

