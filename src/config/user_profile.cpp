#include "session/config/user_profile.hpp"

#include <sodium/crypto_generichash_blake2b.h>

#include "internal.hpp"
#include "session/config/user_profile.h"
#include "session/state.h"
#include "session/state.hpp"
#include "session/types.hpp"

using namespace session::config;
using session::ustring_view;

UserProfile::UserProfile(ustring_view ed25519_secretkey, std::optional<ustring_view> dumped) :
        ConfigBase{dumped} {
    load_key(ed25519_secretkey);
}

std::optional<std::string_view> UserProfile::get_name() const {
    if (auto* s = data["n"].string(); s && !s->empty())
        return *s;
    return std::nullopt;
}

void UserProfile::set_name(std::string_view new_name) {
    set_nonempty_str(data["n"], new_name);
}

profile_pic UserProfile::get_profile_pic() const {
    profile_pic pic{};
    if (auto* url = data["p"].string(); url && !url->empty())
        pic.url = *url;
    if (auto* key = data["q"].string(); key && key->size() == 32)
        pic.key = {reinterpret_cast<const unsigned char*>(key->data()), 32};
    return pic;
}

void UserProfile::set_profile_pic(std::string_view url, ustring_view key) {
    set_pair_if(!url.empty() && key.size() == 32, data["p"], url, data["q"], key);
}

void UserProfile::set_profile_pic(profile_pic pic) {
    set_profile_pic(pic.url, pic.key);
}

void UserProfile::set_nts_priority(int priority) {
    set_nonzero_int(data["+"], priority);
}

int UserProfile::get_nts_priority() const {
    return data["+"].integer_or(0);
}

void UserProfile::set_nts_expiry(std::chrono::seconds expiry) {
    set_positive_int(data["e"], expiry.count());
}

std::optional<std::chrono::seconds> UserProfile::get_nts_expiry() const {
    if (auto* e = data["e"].integer(); e && *e > 0)
        return std::chrono::seconds{*e};
    return std::nullopt;
}

void UserProfile::set_blinded_msgreqs(std::optional<bool> value) {
    if (!value)
        data["M"].erase();
    else
        data["M"] = static_cast<int>(*value);
}

std::optional<bool> UserProfile::get_blinded_msgreqs() const {
    if (auto* M = data["M"].integer(); M)
        return static_cast<bool>(*M);
    return std::nullopt;
}

using namespace session::state;

extern "C" {

LIBSESSION_C_API const char* state_get_profile_name(const state_object* state) {
    if (auto s = unbox(state).config<UserProfile>().get_name())
        return s->data();
    return nullptr;
}

LIBSESSION_C_API void state_set_profile_name(mutable_state_user_object* state, const char* name) {
    unbox(state).user_profile.set_name(name);
}

LIBSESSION_C_API user_profile_pic state_get_profile_pic(const state_object* state) {
    user_profile_pic p;
    if (auto pic = unbox(state).config<UserProfile>().get_profile_pic(); pic) {
        copy_c_str(p.url, pic.url);
        std::memcpy(p.key, pic.key.data(), 32);
    } else {
        p.url[0] = 0;
    }
    return p;
}

LIBSESSION_C_API void state_set_profile_pic(
        mutable_state_user_object* state, user_profile_pic pic) {
    std::string_view url{pic.url};
    ustring_view key;
    if (!url.empty())
        key = {pic.key, 32};

    unbox(state).user_profile.set_profile_pic(url, key);
}

LIBSESSION_C_API int state_get_profile_nts_priority(const state_object* state) {
    return unbox(state).config<UserProfile>().get_nts_priority();
}

LIBSESSION_C_API void state_set_profile_nts_priority(
        mutable_state_user_object* state, int priority) {
    unbox(state).user_profile.set_nts_priority(priority);
}

LIBSESSION_C_API int state_get_profile_nts_expiry(const state_object* state) {
    return unbox(state).config<UserProfile>().get_nts_expiry().value_or(0s).count();
}

LIBSESSION_C_API void state_set_profile_nts_expiry(mutable_state_user_object* state, int expiry) {
    unbox(state).user_profile.set_nts_expiry(std::max(0, expiry) * 1s);
}

LIBSESSION_C_API int state_get_profile_blinded_msgreqs(const state_object* state) {
    if (auto opt = unbox(state).config<UserProfile>().get_blinded_msgreqs())
        return static_cast<int>(*opt);
    return -1;
}

LIBSESSION_C_API void state_set_profile_blinded_msgreqs(
        mutable_state_user_object* state, int enabled) {
    std::optional<bool> val;
    if (enabled >= 0)
        val = static_cast<bool>(enabled);
    unbox(state).user_profile.set_blinded_msgreqs(val);
}

}  // extern "C"