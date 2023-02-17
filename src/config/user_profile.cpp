#include "session/config/user_profile.h"

#include <sodium/crypto_generichash_blake2b.h>

#include "internal.hpp"
#include "session/config/error.h"
#include "session/config/user_profile.hpp"
#include "session/export.h"
#include "session/types.hpp"

using namespace session::config;
using session::ustring_view;

UserProfile::UserProfile(ustring_view ed25519_secretkey, std::optional<ustring_view> dumped) :
        ConfigBase{dumped} {
    load_key(ed25519_secretkey);
}

LIBSESSION_C_API int user_profile_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    return c_wrapper_init<UserProfile>(conf, ed25519_secretkey_bytes, dumpstr, dumplen, error);
}

std::optional<std::string_view> UserProfile::get_name() const {
    if (auto* s = data["n"].string(); s && !s->empty())
        return *s;
    return std::nullopt;
}
LIBSESSION_C_API const char* user_profile_get_name(const config_object* conf) {
    if (auto s = unbox<UserProfile>(conf)->get_name())
        return s->data();
    return nullptr;
}

void UserProfile::set_name(std::string_view new_name) {
    set_nonempty_str(data["n"], new_name);
}
LIBSESSION_C_API int user_profile_set_name(config_object* conf, const char* name) {
    try {
        unbox<UserProfile>(conf)->set_name(name);
    } catch (const std::exception& e) {
        return set_error(conf, SESSION_ERR_BAD_VALUE, e);
    }
    return 0;
}

profile_pic UserProfile::get_profile_pic() const {
    profile_pic pic{};
    if (auto* url = data["p"].string(); url && !url->empty())
        pic.url = *url;
    if (auto* key = data["q"].string(); key && key->size() == 32)
        pic.key = {reinterpret_cast<const unsigned char*>(key->data()), 32};
    return pic;
}

LIBSESSION_C_API user_profile_pic user_profile_get_pic(const config_object* conf) {
    user_profile_pic p;
    if (auto pic = unbox<UserProfile>(conf)->get_profile_pic(); pic) {
        copy_c_str(p.url, pic.url);
        std::memcpy(p.key, pic.key.data(), 32);
    } else {
        p.url[0] = 0;
    }
    return p;
}

void UserProfile::set_profile_pic(std::string_view url, ustring_view key) {
    set_pair_if(!url.empty() && key.size() == 32, data["p"], url, data["q"], key);
}

void UserProfile::set_profile_pic(profile_pic pic) {
    set_profile_pic(pic.url, pic.key);
}

LIBSESSION_C_API int user_profile_set_pic(config_object* conf, user_profile_pic pic) {
    std::string_view url{pic.url};
    ustring_view key;
    if (!url.empty())
        key = {pic.key, 32};

    try {
        unbox<UserProfile>(conf)->set_profile_pic(url, key);
    } catch (const std::exception& e) {
        return set_error(conf, SESSION_ERR_BAD_VALUE, e);
    }

    return 0;
}
