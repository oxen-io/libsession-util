#pragma once

#include <cassert>
#include <memory>

#include "session/config/base.hpp"
#include "session/config/error.h"
#include "session/types.hpp"

namespace session::config {

template <typename ConfigT>
[[nodiscard]] int c_wrapper_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    assert(ed25519_secretkey_bytes);
    ustring_view ed25519_secretkey{ed25519_secretkey_bytes, 32};
    auto c_conf = std::make_unique<config_object>();
    auto c = std::make_unique<internals<ConfigT>>();
    std::optional<ustring_view> dump;
    if (dumpstr && dumplen)
        dump.emplace(dumpstr, dumplen);

    try {
        c->config = std::make_unique<ConfigT>(ed25519_secretkey, dump);
    } catch (const std::exception& e) {
        if (error) {
            std::string msg = e.what();
            if (msg.size() > 255)
                msg.resize(255);
            std::memcpy(error, msg.c_str(), msg.size() + 1);
        }
        return SESSION_ERR_INVALID_DUMP;
    }

    c_conf->internals = c.release();
    c_conf->last_error = nullptr;
    *conf = c_conf.release();
    return SESSION_ERR_NONE;
}

template <size_t N>
void copy_c_str(char (&dest)[N], std::string_view src) {
    if (src.size() >= N)
        src.remove_suffix(src.size() - N - 1);
    std::memcpy(dest, src.data(), src.size());
    dest[src.size()] = 0;
}

}  // namespace session::config
