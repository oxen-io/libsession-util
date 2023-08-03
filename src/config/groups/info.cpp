#include "session/config/groups/info.hpp"

#include <oxenc/hex.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <variant>

#include "../internal.hpp"
//#include "session/config/groups/info.h"
#include "session/config/error.h"
#include "session/export.h"
#include "session/types.hpp"
#include "session/util.hpp"

namespace session::config::groups {

using namespace std::literals;
using session::ustring_view;

Info::Info(
        const std::vector<ustring_view>& keys,
        ustring_view ed25519_pubkey,
        std::optional<ustring_view> ed25519_secretkey,
        std::optional<ustring_view> dumped) :
        ConfigBase{dumped, ed25519_pubkey, ed25519_secretkey} {
    for (const auto& k : keys)
        add_key(k);
}

std::optional<std::string_view> Info::get_name() const {
    if (auto* s = data["n"].string(); s && !s->empty())
        return *s;
    return std::nullopt;
}

void Info::set_name(std::string_view new_name) {
    set_nonempty_str(data["n"], new_name);
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
