#include "session/config/contacts.hpp"

#include <oxenc/hex.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <variant>

#include "session/config/contacts.h"
#include "session/config/error.h"
#include "session/export.h"
#include "session/types.hpp"
#include "session/util.hpp"

using namespace std::literals;
using namespace session::config;
using session::ustring_view;

namespace {

void check_session_id(std::string_view session_id) {
    if (session_id.size() != 66 || !oxenc::is_hex(session_id))
        throw std::invalid_argument{
                "Invalid pubkey: expected 66 hex digits, got " + std::to_string(session_id.size()) +
                " and/or not hex"};
}

std::string session_id_to_bytes(std::string_view session_id) {
    check_session_id(session_id);
    return oxenc::from_hex(session_id);
}

}  // namespace

contact_info::contact_info(std::string sid) : session_id{std::move(sid)} {
    check_session_id(session_id);
}

Contacts::Contacts(ustring_view ed25519_secretkey, std::optional<ustring_view> dumped) :
        ConfigBase{dumped} {
    load_key(ed25519_secretkey);
}

LIBSESSION_C_API int contacts_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    assert(ed25519_secretkey_bytes);
    ustring_view ed25519_secretkey{ed25519_secretkey_bytes, 32};
    auto c_conf = std::make_unique<config_object>();
    auto c = std::make_unique<internals<Contacts>>();
    std::optional<ustring_view> dump;
    if (dumpstr && dumplen)
        dump.emplace(dumpstr, dumplen);

    try {
        c->config = std::make_unique<Contacts>(ed25519_secretkey, dump);
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

// Digs into a dict to get out a std::string_view, if it's there with a non-empty string; otherwise
// returns nullopt.
static std::optional<std::string_view> maybe_sv(const dict& d, const char* key) {
    if (auto it = d.find(key); it != d.end())
        if (auto* sc = std::get_if<scalar>(&it->second))
            if (auto* s = std::get_if<std::string>(sc); s && !s->empty())
                return *s;
    return std::nullopt;
}
// Digs into a dict to get out an int64_t; nullopt if not there (or not int)
static std::optional<int64_t> maybe_int(const dict& d, const char* key) {
    if (auto it = d.find(key); it != d.end())
        if (auto* sc = std::get_if<scalar>(&it->second))
            if (auto* i = std::get_if<int64_t>(sc))
                return *i;
    return std::nullopt;
}

void contact_info::load(const dict& info_dict) {
    name = maybe_sv(info_dict, "n");
    nickname = maybe_sv(info_dict, "N");

    auto url = maybe_sv(info_dict, "p");
    auto key = maybe_sv(info_dict, "q");
    if (url && key && !url->empty() && !key->empty())
        profile_picture.emplace(*url, to_unsigned_sv(*key));
    else
        profile_picture.reset();

    approved = maybe_int(info_dict, "a").value_or(0);
    approved_me = maybe_int(info_dict, "A").value_or(0);
    blocked = maybe_int(info_dict, "b").value_or(0);
}

std::optional<contact_info> Contacts::get(std::string_view pubkey_hex) const {
    std::string pubkey = session_id_to_bytes(pubkey_hex);

    auto* info_dict = data["c"][pubkey].dict();
    if (!info_dict)
        return std::nullopt;

    auto result = std::make_optional<contact_info>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

contact_info Contacts::get_or_default(std::string_view pubkey_hex) const {
    if (auto maybe = get(pubkey_hex))
        return *std::move(maybe);

    return contact_info{std::string{pubkey_hex}};
}

void Contacts::set(const contact_info& contact) {
    std::string pk = session_id_to_bytes(contact.session_id);
    auto info = data["c"][pk];

    // This key is here to keep the session_id entry alive even when we have no other keys.  It has
    // no other purpose.
    info["!"] = ""sv;

    if (contact.name && !contact.name->empty())
        info["n"] = *contact.name;
    else
        info["n"].erase();

    if (contact.nickname && !contact.nickname->empty())
        info["N"] = *contact.nickname;
    else
        info["N"].erase();

    if (contact.profile_picture && !contact.profile_picture->url.empty() &&
        !contact.profile_picture->key.empty()) {
        info["p"] = contact.profile_picture->url;
        info["q"] = contact.profile_picture->key;
    } else {
        info["p"].erase();
        info["q"].erase();
    }

    if (contact.approved)
        info["a"] = 1;
    else
        info["a"].erase();

    if (contact.approved_me)
        info["A"] = 1;
    else
        info["A"].erase();

    if (contact.blocked)
        info["b"] = 1;
    else
        info["b"].erase();
}

void Contacts::set_name(std::string_view session_id, std::string_view name) {
    auto c = get_or_default(session_id);
    c.name = name;
    set(c);
}
void Contacts::set_nickname(std::string_view session_id, std::string_view nickname) {
    auto c = get_or_default(session_id);
    c.nickname = nickname;
    set(c);
}
void Contacts::set_profile_pic(std::string_view session_id, profile_pic pic) {
    auto c = get_or_default(session_id);
    c.profile_picture = std::move(pic);
    set(c);
}
void Contacts::set_approved(std::string_view session_id, bool approved) {
    auto c = get_or_default(session_id);
    c.approved = approved;
    set(c);
}
void Contacts::set_approved_me(std::string_view session_id, bool approved_me) {
    auto c = get_or_default(session_id);
    c.approved_me = approved_me;
    set(c);
}
void Contacts::set_blocked(std::string_view session_id, bool blocked) {
    auto c = get_or_default(session_id);
    c.blocked = blocked;
    set(c);
}

bool Contacts::erase(std::string_view session_id) {
    std::string pk = session_id_to_bytes(session_id);
    auto info = data["c"][pk];
    bool ret = info.exists();
    info.erase();
    return ret;
}

/// Load _val from the current iterator position; if it is invalid, skip to the next key until we
/// find one that is valid (or hit the end).
void Contacts::const_contact_iterator::_load_info() {
    while (_it != _contacts->end()) {
        if (_it->first.size() == 33) {
            if (auto* info_dict = std::get_if<dict>(&_it->second)) {
                _val = std::make_shared<contact_info>(oxenc::to_hex(_it->first));
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

bool Contacts::const_contact_iterator::operator==(const const_contact_iterator& other) const {
    if (!_contacts && !other._contacts)
        return true;  // Both are end tombstones
    if (!other._contacts)
        // other is an "end" tombstone: return whether we are at the end
        return _it == _contacts->end();
    return _it == other._it;
}

Contacts::const_contact_iterator& Contacts::const_contact_iterator::operator++() {
    ++_it;
    _load_info();
    return *this;
}
