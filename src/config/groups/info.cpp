#include "session/config/groups/info.hpp"

#include <oxenc/hex.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <variant>

#include "../internal.hpp"
#include "session/config/error.h"
#include "session/config/groups/info.h"
#include "session/export.h"
#include "session/state.h"
#include "session/state.hpp"
#include "session/types.hpp"
#include "session/util.hpp"

using namespace std::literals;

namespace session::config::groups {

Info::Info(
        ustring_view ed25519_pubkey,
        std::optional<ustring_view> ed25519_secretkey,
        std::optional<ustring_view> dumped) :
        ConfigBase{dumped, ed25519_pubkey, ed25519_secretkey},
        id{"03" + oxenc::to_hex(ed25519_pubkey.begin(), ed25519_pubkey.end())} {}

std::optional<std::string_view> Info::get_name() const {
    if (auto* s = data["n"].string(); s && !s->empty())
        return *s;
    return std::nullopt;
}

void Info::set_name(std::string_view new_name) {
    if (new_name.size() > NAME_MAX_LENGTH)
        new_name = new_name.substr(0, NAME_MAX_LENGTH);
    set_nonempty_str(data["n"], new_name);
}

std::optional<std::string_view> Info::get_description() const {
    if (auto* s = data["o"].string(); s && !s->empty())
        return *s;
    return std::nullopt;
}

void Info::set_description(std::string_view new_desc) {
    if (new_desc.size() > DESCRIPTION_MAX_LENGTH)
        new_desc = new_desc.substr(0, DESCRIPTION_MAX_LENGTH);
    set_nonempty_str(data["o"], new_desc);
}

profile_pic Info::get_profile_pic() const {
    profile_pic pic{};
    if (auto* url = data["p"].string(); url && !url->empty())
        pic.url = *url;
    if (auto* key = data["q"].string(); key && key->size() == 32)
        pic.key = {reinterpret_cast<const unsigned char*>(key->data()), 32};
    return pic;
}

void Info::set_profile_pic(std::string_view url, ustring_view key) {
    set_pair_if(!url.empty() && key.size() == 32, data["p"], url, data["q"], key);
}

void Info::set_profile_pic(profile_pic pic) {
    set_profile_pic(pic.url, pic.key);
}

std::optional<std::chrono::seconds> Info::get_expiry_timer() const {
    if (auto exp = data["E"].integer())
        return *exp * 1s;
    return std::nullopt;
}

void Info::set_expiry_timer(std::chrono::seconds expiration_timer) {
    set_positive_int(data["E"], expiration_timer.count());
}

void Info::set_created(int64_t timestamp) {
    set_positive_int(data["c"], timestamp);
}

std::optional<int64_t> Info::get_created() const {
    if (auto* ts = data["c"].integer())
        return *ts;
    return std::nullopt;
}

void Info::set_delete_before(int64_t timestamp) {
    set_positive_int(data["d"], timestamp);
}

std::optional<int64_t> Info::get_delete_before() const {
    if (auto* ts = data["d"].integer())
        return *ts;
    return std::nullopt;
}

void Info::set_delete_attach_before(int64_t timestamp) {
    set_positive_int(data["D"], timestamp);
}

std::optional<int64_t> Info::get_delete_attach_before() const {
    if (auto* ts = data["D"].integer())
        return *ts;
    return std::nullopt;
}

void Info::destroy_group() {
    set_flag(data["!"], true);
}

bool Info::is_destroyed() const {
    if (auto* ts = data["!"].integer(); ts && *ts > 0)
        return true;
    return false;
}

}  // namespace session::config::groups

using namespace session;
using namespace session::state;
using namespace session::config;

LIBSESSION_C_API const size_t GROUP_INFO_NAME_MAX_LENGTH = groups::Info::NAME_MAX_LENGTH;
LIBSESSION_C_API const size_t GROUP_INFO_DESCRIPTION_MAX_LENGTH =
        groups::Info::DESCRIPTION_MAX_LENGTH;

LIBSESSION_C_API bool state_get_groups_info_name(
        const state_object* state, const char* pubkey_hex, char* name) {
    try {
        if (auto s = unbox(state).config<groups::Info>({pubkey_hex, 66}).get_name()) {
            std::string res = {s->data(), s->size()};
            if (res.size() > groups::Info::NAME_MAX_LENGTH)
                res.resize(groups::Info::NAME_MAX_LENGTH);
            std::memcpy(name, res.c_str(), res.size() + 1);
            return true;
        }
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API void state_set_groups_info_name(
        mutable_state_group_object* state, const char* name) {
    unbox(state).info.set_name(name);
}

LIBSESSION_C_API bool state_get_groups_info_description(
        const state_object* state, const char* pubkey_hex, char* description) {
    try {
        if (auto s = unbox(state).config<groups::Info>({pubkey_hex, 66}).get_description()) {
            std::string res = {s->data(), s->size()};
            if (res.size() > groups::Info::DESCRIPTION_MAX_LENGTH)
                res.resize(groups::Info::DESCRIPTION_MAX_LENGTH);
            std::memcpy(description, res.c_str(), res.size() + 1);
            return true;
        }
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API void state_set_groups_info_description(
        mutable_state_group_object* state, const char* description) {
    unbox(state).info.set_description(description);
}

LIBSESSION_C_API bool state_get_groups_info_pic(
        const state_object* state, const char* pubkey_hex, user_profile_pic* pic) {
    try {
        if (auto p = unbox(state).config<groups::Info>({pubkey_hex, 66}).get_profile_pic()) {
            copy_c_str(pic->url, p.url);
            std::memcpy(pic->key, p.key.data(), 32);
            return true;
        }
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API void state_set_groups_info_pic(
        mutable_state_group_object* state, user_profile_pic pic) {
    std::string_view url{pic.url};
    ustring_view key;
    if (!url.empty())
        key = {pic.key, 32};

    unbox(state).info.set_profile_pic(url, key);
}

LIBSESSION_C_API bool state_get_groups_info_expiry_timer(
        const state_object* state, const char* pubkey_hex, int* timer) {
    try {
        *timer = unbox(state)
                         .config<groups::Info>({pubkey_hex, 66})
                         .get_expiry_timer()
                         .value_or(0s)
                         .count();
        return true;
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API void state_set_groups_info_expiry_timer(
        mutable_state_group_object* state, int expiry) {
    unbox(state).info.set_expiry_timer(std::max(0, expiry) * 1s);
}

LIBSESSION_C_API bool state_get_groups_info_created(
        const state_object* state, const char* pubkey_hex, int64_t* created) {
    try {
        *created = unbox(state).config<groups::Info>({pubkey_hex, 66}).get_created().value_or(0);
        return true;
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API void groups_info_set_created(mutable_state_group_object* state, int64_t ts) {
    unbox(state).info.set_created(std::max<int64_t>(0, ts));
}

LIBSESSION_C_API bool state_get_groups_info_delete_before(
        const state_object* state, const char* pubkey_hex, int64_t* delete_before) {
    try {
        *delete_before =
                unbox(state).config<groups::Info>({pubkey_hex, 66}).get_delete_before().value_or(0);
        return true;
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API void state_set_groups_info_delete_before(
        mutable_state_group_object* state, int64_t ts) {
    unbox(state).info.set_delete_before(std::max<int64_t>(0, ts));
}

LIBSESSION_C_API bool state_get_groups_info_attach_delete_before(
        const state_object* state, const char* pubkey_hex, int64_t* delete_before) {
    try {
        *delete_before = unbox(state)
                                 .config<groups::Info>({pubkey_hex, 66})
                                 .get_delete_attach_before()
                                 .value_or(0);
        return true;
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API void state_set_groups_info_attach_delete_before(
        mutable_state_group_object* state, int64_t ts) {
    unbox(state).info.set_delete_attach_before(std::max<int64_t>(0, ts));
}

LIBSESSION_C_API bool state_groups_info_is_destroyed(
        const state_object* state, const char* pubkey_hex) {
    try {
        if (unbox(state).config<groups::Info>({pubkey_hex, 66}).is_destroyed()) {
            return true;
        }
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API void state_destroy_group(mutable_state_group_object* state) {
    unbox(state).info.destroy_group();
}
