#pragma once

#include <oxenc/hex.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "session/config/base.h"
#include "session/config/namespaces.h"
#include "session/config/namespaces.hpp"

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

inline int64_t get_timestamp_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}

inline std::string_view to_sv(ustring_view x) {
    return {reinterpret_cast<const char*>(x.data()), x.size()};
}
inline ustring_view to_usv(std::string_view x) {
    return {reinterpret_cast<const unsigned char*>(x.data()), x.size()};
}
template <size_t N>
ustring_view to_usv(const std::array<unsigned char, N>& data) {
    return {data.data(), N};
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

template <typename Container>
std::set<typename Container::value_type> as_set(const Container& c) {
    return {c.begin(), c.end()};
}

template <typename... T>
std::set<std::common_type_t<T...>> make_set(T&&... args) {
    return {std::forward<T>(args)...};
}

template <typename C>
std::vector<std::basic_string_view<C>> view_vec(std::vector<std::basic_string<C>>&& v) = delete;
template <typename C>
std::vector<std::basic_string_view<C>> view_vec(const std::vector<std::basic_string<C>>& v) {
    std::vector<std::basic_string_view<C>> vv;
    vv.reserve(v.size());
    std::copy(v.begin(), v.end(), std::back_inserter(vv));
    return vv;
}

struct last_store_data {
    session::config::Namespace namespace_;
    std::string pubkey;
    uint64_t timestamp;
    ustring data;
};
struct last_send_data {
    std::string pubkey;
    ustring payload;
    bool (*response_cb)(
            bool success,
            int16_t status_code,
            const unsigned char* res,
            size_t reslen,
            void* callback_context);
    void* app_ctx;
    void* callback_context;
};

inline void c_store_callback(
        NAMESPACE namespace_,
        const char* pubkey,
        uint64_t timestamp_ms,
        const unsigned char* data,
        size_t data_len,
        void* ctx) {
    *static_cast<std::optional<last_store_data>*>(ctx) = last_store_data{
            static_cast<session::config::Namespace>(namespace_),
            {pubkey, 66},
            timestamp_ms,
            {data, data_len}};
}

inline void c_send_callback(
        const char* pubkey,
        const unsigned char* data,
        size_t data_len,
        bool (*response_cb)(
                bool success,
                int16_t status_code,
                const unsigned char* res,
                size_t reslen,
                void* callback_context),
        void* app_ctx,
        void* callback_context) {
    *static_cast<std::optional<last_send_data>*>(app_ctx) =
            last_send_data{{pubkey, 66}, {data, data_len}, response_cb, app_ctx, callback_context};
}
