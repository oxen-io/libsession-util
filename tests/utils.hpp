#pragma once

#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <string>
#include <string_view>

#include "session/config/base.h"

using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;

inline ustring operator""_bytes(const char* x, size_t n) {
    return {reinterpret_cast<const unsigned char*>(x), n};
}
inline ustring operator""_hexbytes(const char* x, size_t n) {
    ustring bytes;
    oxenc::from_hex(x, x + n, std::back_inserter(bytes));
    return bytes;
}

inline std::string to_hex(ustring_view bytes) {
    std::string hex;
    oxenc::to_hex(bytes.begin(), bytes.end(), std::back_inserter(hex));
    return hex;
}

inline constexpr auto operator""_kiB(unsigned long long kiB) {
    return kiB * 1024;
}

inline std::string_view to_sv(ustring_view x) {
    return {reinterpret_cast<const char*>(x.data()), x.size()};
}
inline ustring_view to_usv(std::string_view x) {
    return {reinterpret_cast<const unsigned char*>(x.data()), x.size()};
}

inline std::string printable(ustring_view x) {
    std::string p;
    for (auto c : x) {
        if (c >= 0x20 && c <= 0x7e)
            p += c;
        else
            p += "\\x" + oxenc::to_hex(&c, &c + 1);
    }
    return p;
}
inline std::string printable(std::string_view x) {
    return printable(to_usv(x));
}
std::string printable(const unsigned char* x) = delete;
inline std::string printable(const unsigned char* x, size_t n) {
    return printable({x, n});
}

inline void log_msg(config_log_level lvl, const char* msg, void*) {
    INFO((lvl == LOG_LEVEL_ERROR     ? "ERROR"
          : lvl == LOG_LEVEL_WARNING ? "Warning"
          : lvl == LOG_LEVEL_INFO    ? "Info"
                                     : "debug")
         << ": " << msg);
}
