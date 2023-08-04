#include "session/config/groups/members.hpp"
#include <oxenc/hex.h>

#include "../internal.hpp"

namespace session::config::groups {

Members::Members(
        const std::vector<ustring_view>& keys,
        ustring_view ed25519_pubkey,
        std::optional<ustring_view> ed25519_secretkey,
        std::optional<ustring_view> dumped) :
        ConfigBase{dumped, ed25519_pubkey, ed25519_secretkey} {
    for (const auto& k : keys)
        add_key(k, false);
}

std::optional<member> Members::get(std::string_view pubkey_hex) const {
    std::string pubkey = session_id_to_bytes(pubkey_hex);

    auto* info_dict = data["m"][pubkey].dict();
    if (!info_dict)
        return std::nullopt;

    auto result = std::make_optional<member>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

member Members::get_or_construct(std::string_view pubkey_hex) const {
    if (auto maybe = get(pubkey_hex))
        return *std::move(maybe);

    return member{std::string{pubkey_hex}};
}

void Members::set(const member& mem) {

    std::string pk = session_id_to_bytes(mem.session_id);
    auto info = data["m"][pk];

    // Always set the name, even if empty, to keep the dict from getting pruned if there are no
    // other entries.
    info["n"] = mem.name.substr(0, member::MAX_NAME_LENGTH);

    set_pair_if(
            mem.profile_picture,
            info["p"],
            mem.profile_picture.url,
            info["q"],
            mem.profile_picture.key);

    set_flag(info["A"], mem.admin);
    set_positive_int(info["P"], mem.admin ? 0 : mem.promotion_status);
    set_positive_int(info["I"], mem.admin ? 0 : mem.invite_status);
}

void member::load(const dict& info_dict) {
    name = maybe_string(info_dict, "n").value_or("");

    auto url = maybe_string(info_dict, "p");
    auto key = maybe_ustring(info_dict, "q");
    if (url && key && !url->empty() && key->size() == 32) {
        profile_picture.url = std::move(*url);
        profile_picture.key = std::move(*key);
    } else {
        profile_picture.clear();
    }

    admin = maybe_int(info_dict, "A").value_or(0);
    invite_status = admin ? 0 : maybe_int(info_dict, "I").value_or(0);
    promotion_status = admin ? 0 : maybe_int(info_dict, "P").value_or(0);
}

/// Load _val from the current iterator position; if it is invalid, skip to the next key until we
/// find one that is valid (or hit the end).
void Members::iterator::_load_info() {
    while (_it != _members->end()) {
        if (_it->first.size() == 33) {
            if (auto* info_dict = std::get_if<dict>(&_it->second)) {
                _val = std::make_shared<member>(oxenc::to_hex(_it->first));
                auto hex = oxenc::to_hex(_it->first);
                _val->load(*info_dict);
                return;
            }
        }

        // We found something we don't understand (wrong pubkey size, or not a dict value) so skip
        // it.
        ++_it;
    }
}

bool Members::iterator::operator==(const iterator& other) const {
    if (!_members && !other._members)
        return true;  // Both are end tombstones
    if (!other._members)
        // other is an "end" tombstone: return whether we are at the end
        return _it == _members->end();
    if (!_members)
        // we are an "end" tombstone: return whether the other one is at the end
        return other._it == other._members->end();
    return _it == other._it;
}

bool Members::iterator::done() const {
    return !_members || _it == _members->end();
}

Members::iterator& Members::iterator::operator++() {
    ++_it;
    _load_info();
    return *this;
}

bool Members::erase(std::string_view session_id) {
    std::string pk = session_id_to_bytes(session_id);
    auto info = data["m"][pk];
    bool ret = info.exists();
    info.erase();
    return ret;
}


member::member(std::string sid) : session_id{std::move(sid)} {
    check_session_id(session_id);
}

}  // namespace session::config::groups
