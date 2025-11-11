#include "event.hpp"

#include <iomanip>
#include <sstream>

namespace wslmon {
namespace {
std::string format_timestamp(const std::chrono::system_clock::time_point &tp) {
    using namespace std::chrono;
    auto time_t_value = system_clock::to_time_t(tp);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &time_t_value);
#else
    gmtime_r(&time_t_value, &tm);
#endif
    auto fractional = duration_cast<microseconds>(tp.time_since_epoch()).count() % 1000000;
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setw(6) << std::setfill('0') << fractional << "Z";
    return oss.str();
}

std::string escape(std::string_view input) {
    std::string out;
    out.reserve(input.size() + 2);
    for (char c : input) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    std::ostringstream oss;
                    oss << "\\u" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c));
                    out += oss.str();
                } else {
                    out += c;
                }
        }
    }
    return out;
}
}  // namespace

std::string SerializeEvent(const EventRecord &record) {
    std::ostringstream oss;
    oss << '{';
    oss << "\"timestamp\":\"" << escape(format_timestamp(record.timestamp)) << "\",";
    oss << "\"sequence\":" << record.sequence << ',';
    oss << "\"source\":\"" << escape(record.source) << "\",";
    oss << "\"category\":\"" << escape(record.category) << "\",";
    oss << "\"severity\":\"" << escape(record.severity) << "\",";
    oss << "\"message\":\"" << escape(record.message) << "\",";
    oss << "\"attributes\":[";
    for (std::size_t i = 0; i < record.attributes.size(); ++i) {
        const auto &attr = record.attributes[i];
        oss << '{'
            << "\"key\":\"" << escape(attr.key) << "\","
            << "\"value\":\"" << escape(attr.value) << "\"" << '}';
        if (i + 1 < record.attributes.size()) {
            oss << ',';
        }
    }
    oss << "]}";
    return oss.str();
}

}  // namespace wslmon

