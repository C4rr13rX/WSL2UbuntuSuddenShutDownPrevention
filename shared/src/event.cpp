#include "event.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

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

std::string json_unescape(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (c != '\\') {
            out.push_back(c);
            continue;
        }
        if (i + 1 >= input.size()) {
            break;
        }
        char esc = input[++i];
        switch (esc) {
            case '\\':
                out.push_back('\\');
                break;
            case '"':
                out.push_back('"');
                break;
            case 'n':
                out.push_back('\n');
                break;
            case 'r':
                out.push_back('\r');
                break;
            case 't':
                out.push_back('\t');
                break;
            case 'u': {
                if (i + 4 >= input.size()) {
                    break;
                }
                unsigned int code = 0;
                for (int j = 0; j < 4; ++j) {
                    char hex = input[i + j + 1];
                    code <<= 4;
                    if (hex >= '0' && hex <= '9') {
                        code |= static_cast<unsigned int>(hex - '0');
                    } else if (hex >= 'a' && hex <= 'f') {
                        code |= static_cast<unsigned int>(hex - 'a' + 10);
                    } else if (hex >= 'A' && hex <= 'F') {
                        code |= static_cast<unsigned int>(hex - 'A' + 10);
                    }
                }
                i += 4;
                if (code <= 0x7F) {
                    out.push_back(static_cast<char>(code));
                } else if (code <= 0x7FF) {
                    out.push_back(static_cast<char>(0xC0 | ((code >> 6) & 0x1F)));
                    out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                } else {
                    out.push_back(static_cast<char>(0xE0 | ((code >> 12) & 0x0F)));
                    out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                }
                break;
            }
            default:
                out.push_back(esc);
                break;
        }
    }
    return out;
}

bool extract_string(std::string_view json, std::string_view key, std::string &value) {
    const std::string pattern = std::string("\"") + std::string(key) + "\":\"";
    auto pos = json.find(pattern);
    if (pos == std::string_view::npos) {
        return false;
    }
    pos += pattern.size();
    std::string raw;
    bool escaping = false;
    for (std::size_t i = pos; i < json.size(); ++i) {
        char c = json[i];
        if (!escaping) {
            if (c == '\\') {
                escaping = true;
            } else if (c == '"') {
                value = json_unescape(raw);
                return true;
            } else {
                raw.push_back(c);
            }
        } else {
            raw.push_back('\\');
            raw.push_back(c);
            escaping = false;
        }
    }
    return false;
}

bool extract_uint64(std::string_view json, std::string_view key, std::uint64_t &value) {
    const std::string pattern = std::string("\"") + std::string(key) + "\":";
    auto pos = json.find(pattern);
    if (pos == std::string_view::npos) {
        return false;
    }
    pos += pattern.size();
    std::size_t end = pos;
    while (end < json.size() && std::isdigit(static_cast<unsigned char>(json[end]))) {
        ++end;
    }
    if (end == pos) {
        return false;
    }
    try {
        value = std::stoull(std::string(json.substr(pos, end - pos)));
        return true;
    } catch (const std::exception &) {
        return false;
    }
}

bool parse_timestamp(std::string_view json,
                     std::string_view key,
                     std::chrono::system_clock::time_point &tp) {
    std::string ts;
    if (!extract_string(json, key, ts)) {
        return false;
    }
    if (ts.size() < 19) {
        return false;
    }
    std::tm parsed{};
    std::istringstream ss(ts.substr(0, 19));
    ss >> std::get_time(&parsed, "%Y-%m-%dT%H:%M:%S");
    if (ss.fail()) {
        return false;
    }
#ifdef _WIN32
    std::time_t time_value = _mkgmtime(&parsed);
#else
    std::time_t time_value = timegm(&parsed);
#endif
    if (time_value == static_cast<std::time_t>(-1)) {
        return false;
    }
    tp = std::chrono::system_clock::from_time_t(time_value);
    auto dot_pos = ts.find('.');
    if (dot_pos != std::string::npos) {
        auto frac = ts.substr(dot_pos + 1);
        if (!frac.empty() && frac.back() == 'Z') {
            frac.pop_back();
        }
        while (frac.size() < 6) {
            frac.push_back('0');
        }
        try {
            auto micros = std::stoll(frac.substr(0, 6));
            tp += std::chrono::microseconds(micros);
        } catch (const std::exception &) {
        }
    }
    return true;
}

bool extract_attributes(std::string_view json, std::vector<EventAttribute> &attributes) {
    const std::string pattern = "\"attributes\":[";
    auto pos = json.find(pattern);
    if (pos == std::string_view::npos) {
        return false;
    }
    pos += pattern.size();
    auto end = json.find(']', pos);
    if (end == std::string_view::npos) {
        return false;
    }
    std::string_view array_view = json.substr(pos, end - pos);
    std::size_t index = 0;
    attributes.clear();
    while (index < array_view.size()) {
        auto start = array_view.find('{', index);
        if (start == std::string_view::npos) {
            break;
        }
        auto close = array_view.find('}', start);
        if (close == std::string_view::npos) {
            return false;
        }
        std::string_view item = array_view.substr(start, close - start + 1);
        EventAttribute attribute;
        extract_string(item, "key", attribute.key);
        extract_string(item, "value", attribute.value);
        if (!attribute.key.empty() || !attribute.value.empty()) {
            attributes.push_back(std::move(attribute));
        }
        index = close + 1;
    }
    return true;
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

    std::vector<EventAttribute> attributes = record.attributes;
    std::sort(attributes.begin(), attributes.end(), [](const auto &lhs, const auto &rhs) {
        if (lhs.key == rhs.key) {
            return lhs.value < rhs.value;
        }
        return lhs.key < rhs.key;
    });

    oss << "\"attributes\":[";
    for (std::size_t i = 0; i < attributes.size(); ++i) {
        const auto &attr = attributes[i];
        oss << "{\"key\":\"" << escape(attr.key) << "\",\"value\":\"" << escape(attr.value) << "\"}";
        if (i + 1 < attributes.size()) {
            oss << ',';
        }
    }
    oss << "]}";
    return oss.str();
}

bool DeserializeEvent(std::string_view json, EventRecord &record) {
    record = EventRecord{};
    if (!parse_timestamp(json, "timestamp", record.timestamp)) {
        return false;
    }
    if (!extract_uint64(json, "sequence", record.sequence)) {
        record.sequence = 0;
    }
    extract_string(json, "source", record.source);
    extract_string(json, "category", record.category);
    extract_string(json, "severity", record.severity);
    extract_string(json, "message", record.message);
    extract_attributes(json, record.attributes);
    return true;
}

}  // namespace wslmon

