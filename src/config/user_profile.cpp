#include "session/config/user_profile.hpp"

#include <sodium/crypto_generichash_blake2b.h>

#include "internal.hpp"
#include "session/types.hpp"

using namespace session::config;
using session::ustring_view;

UserProfile::UserProfile(
        ustring_view ed25519_secretkey,
        std::optional<ustring_view> dumped,
        std::optional<session::state::State*> parent_state) :
        ConfigBase{parent_state, dumped} {
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
