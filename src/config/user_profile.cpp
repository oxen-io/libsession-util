#include "session/config/user_profile.h"

#include "session/config/error.h"
#include "session/config/user_profile.hpp"

using namespace session::config;

LIBSESSION_C_API int user_profile_init(
        config_object** conf, const char* dump, size_t dumplen, char* error) {
    auto c_conf = std::make_unique<config_object>();
    auto c = std::make_unique<internals<UserProfile>>();
    try {
        if (dump && dumplen)
            c->config = std::make_unique<UserProfile>(std::string_view{dump, dumplen});
        else
            c->config = std::make_unique<UserProfile>();
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

const std::string* UserProfile::get_name() const {
    return data["n"].string();
}
LIBSESSION_C_API const char* user_profile_get_name(const config_object* conf) {
    if (auto* s = unbox<UserProfile>(conf)->get_name())
        return s->c_str();
    return nullptr;
}

void UserProfile::set_name(std::string_view new_name) {
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

std::pair<const std::string*, const std::string*> UserProfile::get_profile_pic() const {
    auto* url = data["p"].string();
    auto* key = data["q"].string();
    if (!url || !key || url->empty() || key->empty()) {
        // We return nullptr for both if *either* is unset:
        url = nullptr;
        key = nullptr;
    }
    return {url, key};
}

LIBSESSION_C_API user_profile_pic user_profile_get_pic(const config_object* conf) {
    auto [url, key] = unbox<UserProfile>(conf)->get_profile_pic();
    return user_profile_pic{
            url ? url->c_str() : nullptr, key ? key->c_str() : nullptr, key ? key->size() : 0};
}

void UserProfile::set_profile_pic(std::string url, std::string key) {
    if (key.empty() || url.empty()) {
        data["p"].erase();
        data["q"].erase();
    } else {
        data["p"] = std::move(url);
        data["q"] = std::move(key);
    }
}

LIBSESSION_C_API int user_profile_set_pic(config_object* conf, user_profile_pic pic) {
    std::string url, key;
    if (pic.url)
        url = pic.url;
    if (pic.key && pic.keylen)
        key.assign(pic.key, pic.keylen);

    try {
        unbox<UserProfile>(conf)->set_profile_pic(std::move(url), std::move(key));
    } catch (const std::exception& e) {
        return set_error(conf, SESSION_ERR_BAD_VALUE, e);
    }

    return 0;
}
