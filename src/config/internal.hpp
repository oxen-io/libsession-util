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

// Throws std::invalid_argument if session_id doesn't look valid
void check_session_id(std::string_view session_id);

// Checks the session_id (throwing if invalid) then returns it as bytes
std::string session_id_to_bytes(std::string_view session_id);

// Validates an open group pubkey; we accept it in hex, base32z, or base64 (padded or unpadded).
// Throws std::invalid_argument if invalid.
void check_encoded_pubkey(std::string_view pk);

// Takes a 32-byte pubkey value encoded as hex, base32z, or base64 and returns the decoded 32 bytes.
// Throws if invalid.
ustring decode_pubkey(std::string_view pk);

// Modifies a string to be (ascii) lowercase.
void make_lc(std::string& s);

// Digs into a config `dict` to get out an int64_t; nullopt if not there (or not int)
std::optional<int64_t> maybe_int(const session::config::dict& d, const char* key);

// Digs into a config `dict` to get out a string; nullopt if not there (or not string)
std::optional<std::string> maybe_string(const session::config::dict& d, const char* key);

// Digs into a config `dict` to get out a ustring; nullopt if not there (or not string)
std::optional<ustring> maybe_ustring(const session::config::dict& d, const char* key);

/// Sets a value to 1 if true, removes it if false.
void set_flag(ConfigBase::DictFieldProxy&& field, bool val);

/// Sets a string value if non-empty, clears it if empty.
void set_nonempty_str(ConfigBase::DictFieldProxy&& field, std::string val);

/// Sets an integer value, if non-zero; removes it if 0.
void set_nonzero_int(ConfigBase::DictFieldProxy&& field, int64_t val);

/// Sets an integer value, if positive; removes it if <= 0.
void set_positive_int(ConfigBase::DictFieldProxy&& field, int64_t val);

}  // namespace session::config
