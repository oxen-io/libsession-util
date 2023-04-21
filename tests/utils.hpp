#pragma once

#include <oxenc/hex.h>

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <set>
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
    return oxenc::to_hex(bytes.begin(), bytes.end());
}
template <typename Char, size_t N, std::enable_if_t<sizeof(Char) == 1, int> = 0>
inline std::string to_hex(const std::array<Char, N>& arr) {
    return oxenc::to_hex(arr.begin(), arr.end());
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
template <size_t N>
inline ustring_view to_usv(const std::array<unsigned char, N>& arr) {
    return {reinterpret_cast<const unsigned char*>(arr.data()), arr.size()};
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

template <typename Container>
std::set<typename Container::value_type> as_set(const Container& c) {
    return {c.begin(), c.end()};
}

template <typename... T>
std::set<std::common_type_t<T...>> make_set(T&&... args) {
    return {std::forward<T>(args)...};
}
