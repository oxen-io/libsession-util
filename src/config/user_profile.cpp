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
    if (new_name.empty())
        data["n"].erase();
    else
        data["n"] = new_name;
}
LIBSESSION_C_API int user_profile_set_name(config_object* conf, const char* name) {
    try {
        unbox<UserProfile>(conf)->set_name(name);
    } catch (const std::exception& e) {
        return set_error(conf, SESSION_ERR_BAD_VALUE, e);
    }
    return 0;
}

std::optional<profile_pic> UserProfile::get_profile_pic() const {
    auto* url = data["p"].string();
    auto* key = data["q"].string();
    if (url && key && !url->empty() && !key->empty())
        return profile_pic{
                *url, {reinterpret_cast<const unsigned char*>(key->data()), key->size()}};
    return std::nullopt;
}

LIBSESSION_C_API user_profile_pic user_profile_get_pic(const config_object* conf) {
    if (auto pic = unbox<UserProfile>(conf)->get_profile_pic(); pic && pic->key.size() == 32)
        return {pic->url.data(), pic->key.data()};

    return {nullptr, nullptr};
}

void UserProfile::set_profile_pic(std::string_view url, ustring_view key) {
    if (key.empty() || url.empty()) {
        data["p"].erase();
        data["q"].erase();
    } else {
        data["p"] = std::string{url};
        data["q"] = std::string{reinterpret_cast<const char*>(key.data()), key.size()};
    }
}

void UserProfile::set_profile_pic(profile_pic pic) {
    set_profile_pic(pic.url, pic.key);
}

LIBSESSION_C_API int user_profile_set_pic(config_object* conf, user_profile_pic pic) {
    std::string_view url;
    ustring_view key;
    if (pic.url)
        url = pic.url;
    if (pic.key)
        key = {pic.key, 32};

    try {
        unbox<UserProfile>(conf)->set_profile_pic(url, key);
    } catch (const std::exception& e) {
        return set_error(conf, SESSION_ERR_BAD_VALUE, e);
    }

    return 0;
}
