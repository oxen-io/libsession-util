#include "session/config/user_groups.hpp"

#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <oxenc/variant.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <charconv>
#include <iterator>
#include <stdexcept>
#include <variant>

#include "internal.hpp"
#include "session/config/error.h"
#include "session/config/user_groups.h"
#include "session/export.h"
#include "session/types.hpp"
#include "session/util.hpp"

using namespace std::literals;
using session::ustring_view;

namespace session::config {

legacy_group_info::legacy_group_info(std::string sid) : session_id{std::move(sid)} {
    check_session_id(session_id);
}

community_info::community_info(const ugroups_community_info& c) :
        community_info{c.base_url, c.room, ustring_view{c.pubkey, 32}} {}

void community_info::into(ugroups_community_info& c) const {
    static_assert(sizeof(c.base_url) == URL_MAX_LENGTH + 1);
    static_assert(sizeof(c.room) == ROOM_MAX_LENGTH + 1);
    copy_c_str(c.base_url, base_url());
    copy_c_str(c.room, room());
    std::memcpy(c.pubkey, pubkey().data(), 32);
    c.priority = priority;
}

static_assert(sizeof(ugroups_legacy_group_info::name) == legacy_group_info::NAME_MAX_LENGTH + 1);

legacy_group_info::legacy_group_info(const ugroups_legacy_group_info& c) :
        session_id{c.session_id, 66},
        name{c.name},
        disappearing_timer{c.disappearing_timer},
        hidden{c.hidden},
        priority{c.priority} {
    assert(name.size() <= NAME_MAX_LENGTH);  // Otherwise the caller messed up
    if (c.have_enc_keys) {
        enc_pubkey.assign(c.enc_pubkey, 32);
        enc_seckey.assign(c.enc_seckey, 32);
    }
}

void legacy_group_info::into(ugroups_legacy_group_info& c) const {
    assert(session_id.size() == 66);
    copy_c_str(c.session_id, session_id);
    copy_c_str(c.name, name);
    c.have_enc_keys = enc_pubkey.size() == 32 && enc_seckey.size() == 32;
    if (c.have_enc_keys) {
        std::memcpy(c.enc_pubkey, enc_pubkey.data(), 32);
        std::memcpy(c.enc_seckey, enc_seckey.data(), 32);
    }
    c.disappearing_timer = disappearing_timer.count();
    c.hidden = hidden;
    c.priority = priority;
}

void legacy_group_info::load(const dict& info_dict) {
    if (auto n = maybe_string(info_dict, "n"))
        name = *n;
    // otherwise leave the current `name` alone at whatever the object was constructed with

    auto enc_pub = maybe_ustring(info_dict, "k");
    auto enc_sec = maybe_ustring(info_dict, "K");
    if (enc_pub && enc_sec && enc_pub->size() == 32 && enc_sec->size() == 32) {
        enc_pubkey = std::move(*enc_pub);
        enc_seckey = std::move(*enc_sec);
    } else {
        enc_pubkey.clear();
        enc_seckey.clear();
    }
    if (auto minutes = maybe_int(info_dict, "E").value_or(0); minutes > 0)
        disappearing_timer = std::chrono::minutes(minutes);
    else
        disappearing_timer = 0min;
    hidden = maybe_int(info_dict, "h").value_or(0);
    priority = std::max<int>(0, maybe_int(info_dict, "+").value_or(0));

    members_.clear();
    if (auto* members = maybe_set(info_dict, "m"))
        for (const auto& field : *members)
            if (auto* s = std::get_if<std::string>(&field))
                if (s->size() == 33 && (*s)[0] == 0x05)
                    members_.emplace_hint(members_.end(), oxenc::to_hex(*s), false);

    if (auto* members = maybe_set(info_dict, "a"))
        for (const auto& field : *members)
            if (auto* s = std::get_if<std::string>(&field))
                if (s->size() == 33 && (*s)[0] == 0x05)
                    members_.emplace(oxenc::to_hex(*s), true);
}

std::pair<size_t, size_t> legacy_group_info::counts() const {
    std::pair<size_t, size_t> counts{0, 0};
    auto& [admins, members] = counts;
    for (const auto& [sid, admin] : members_)
        ++(admin ? admins : members);
    return counts;
}

bool legacy_group_info::insert(std::string session_id, bool admin) {
    check_session_id(session_id);
    auto [it, inserted] = members_.emplace(std::move(session_id), admin);
    if (inserted)
        return true;
    if (it->second != admin) {
        it->second = admin;
        return true;
    }
    return false;
}

bool legacy_group_info::erase(const std::string& session_id) {
    return members_.erase(session_id);
}

void community_info::load(const dict& info_dict) {
    if (auto n = maybe_string(info_dict, "n"))
        set_room(*n);
    priority = std::max<int>(0, maybe_int(info_dict, "+").value_or(0));
}

UserGroups::UserGroups(ustring_view ed25519_secretkey, std::optional<ustring_view> dumped) :
        ConfigBase{dumped} {
    load_key(ed25519_secretkey);
}

ConfigBase::DictFieldProxy UserGroups::community_field(
        const community_info& og, ustring_view* get_pubkey) const {
    auto record = data["o"][og.base_url()];
    if (get_pubkey) {
        auto pkrec = record["#"];
        if (auto pk = pkrec.string_view_or(""); pk.size() == 32)
            *get_pubkey =
                    ustring_view{reinterpret_cast<const unsigned char*>(pk.data()), pk.size()};
    }
    return record["R"][og.room_norm()];
}

std::optional<community_info> UserGroups::get_community(
        std::string_view base_url, std::string_view room) const {
    community_info og{base_url, room};

    ustring_view pubkey;
    if (auto* info_dict = community_field(og, &pubkey).dict()) {
        og.load(*info_dict);
        if (!pubkey.empty())
            og.set_pubkey(pubkey);
        return std::move(og);
    }
    return std::nullopt;
}

community_info UserGroups::get_or_construct_community(
        std::string_view base_url, std::string_view room, ustring_view pubkey) const {
    community_info result{base_url, room, pubkey};

    if (auto* info_dict = community_field(result).dict())
        result.load(*info_dict);

    return result;
}

community_info UserGroups::get_or_construct_community(
        std::string_view base_url, std::string_view room, std::string_view pubkey_encoded) const {
    community_info result{base_url, room, pubkey_encoded};

    if (auto* info_dict = community_field(result).dict())
        result.load(*info_dict);

    return result;
}

std::optional<legacy_group_info> UserGroups::get_legacy_group(std::string_view pubkey_hex) const {
    std::string pubkey = session_id_to_bytes(pubkey_hex);

    auto* info_dict = data["C"][pubkey].dict();
    if (!info_dict)
        return std::nullopt;

    auto result = std::make_optional<legacy_group_info>(std::string{pubkey_hex});
    result->load(*info_dict);
    return result;
}

legacy_group_info UserGroups::get_or_construct_legacy_group(std::string_view pubkey_hex) const {
    if (auto maybe = get_legacy_group(pubkey_hex))
        return *std::move(maybe);

    return legacy_group_info{std::string{pubkey_hex}};
}

void UserGroups::set(const community_info& c) {
    data["o"][c.base_url()]["#"] = c.pubkey();
    auto info = community_field(c);  // data["o"][base]["R"][lc_room]
    info["n"] = c.room();
    set_positive_int(info["+"], c.priority);
}

void UserGroups::set(const legacy_group_info& g) {
    auto info = data["C"][session_id_to_bytes(g.session_id)];
    if (g.name.size() > legacy_group_info::NAME_MAX_LENGTH)
        info["n"] = g.name.substr(0, legacy_group_info::NAME_MAX_LENGTH);
    else
        info["n"] = g.name;

    set_pair_if(
            g.enc_pubkey.size() == 32 && g.enc_seckey.size() == 32,
            info["k"],
            g.enc_pubkey,
            info["K"],
            g.enc_seckey);

    config::set members, admins;
    for (const auto& [member, admin] : g.members_) {
        assert(oxenc::is_hex(member));
        (admin ? admins : members).emplace(oxenc::from_hex(member));
    }
    info["m"] = std::move(members);
    info["a"] = std::move(admins);
    set_positive_int(info["E"], g.disappearing_timer.count());
    set_positive_int(info["+"], g.priority);
    set_flag(info["h"], g.hidden);
}

template <typename Field>
static bool erase_impl(Field convo) {
    bool ret = convo.exists();
    convo.erase();
    return ret;
}

bool UserGroups::erase(const community_info& c) {
    bool gone = erase_impl(community_field(c));
    if (gone) {
        // If this was the last room on the server, also remove the server (otherwise it would
        // persist because of the "#" pubkey).
        auto server_info = data["o"][c.base_url()];
        auto rooms = server_info["R"];
        if (auto* rd = rooms.dict(); !rd || rd->empty()) {
            rooms.erase();
            server_info.erase();
        }
    }
    return gone;
}
bool UserGroups::erase(const legacy_group_info& c) {
    return erase_impl(data["C"][session_id_to_bytes(c.session_id)]);
}

bool UserGroups::erase(const any_group_info& c) {
    return var::visit([this](const auto& c) { return erase(c); }, c);
}
bool UserGroups::erase_community(std::string_view base_url, std::string_view room) {
    return erase(community_info{base_url, room});
}
bool UserGroups::erase_legacy_group(std::string_view id) {
    return erase(legacy_group_info{std::string{id}});
}

UserGroups::iterator UserGroups::erase(iterator it) {
    auto remove_it = it++;
    erase(*remove_it);
    return it;
}

size_t UserGroups::size_communities() const {
    size_t count = 0;
    auto og = data["o"];
    if (auto* servers = og.dict()) {
        for (const auto& [baseurl, info] : *servers) {
            auto server = og[baseurl];
            if (!server["#"].exists<std::string>())
                continue;
            auto rooms = server["R"];
            if (auto* rd = rooms.dict())
                count += rd->size();
        }
    }
    return count;
}

size_t UserGroups::size_legacy_groups() const {
    if (auto* d = data["C"].dict())
        return d->size();
    return 0;
}

size_t UserGroups::size() const {
    return size_communities() + size_legacy_groups();
}

UserGroups::iterator::iterator(const DictFieldRoot& data, bool communities, bool legacy_groups) {
    if (communities)
        if (auto* d = data["o"].dict())
            _it_comm.emplace(d->begin(), d->end());
    if (legacy_groups)
        if (auto* d = data["C"].dict()) {
            _it_legacy = d->begin();
            _end_legacy = d->end();
        }
    _load_val();
}

/// Load _val from the current iterator position; if it is invalid, skip to the next key until we
/// find one that is valid (or hit the end).  We also span across three different iterators: first
/// we exhaust communities, then legacy groups.
///
/// We *always* call this after incrementing the iterators (and after iterator initialization), and
/// this is responsible for making sure that the the _it variables are set up as required.
void UserGroups::iterator::_load_val() {
    if (_it_comm) {
        if (_it_comm->load<community_info>(_val))
            return;
        else
            _it_comm.reset();
    }

    while (_it_legacy) {
        if (*_it_legacy == *_end_legacy) {
            _it_legacy.reset();
            _end_legacy.reset();
            break;
        }

        auto& [k, v] = **_it_legacy;

        if (k.size() == 33 && k[0] == 0x05) {
            if (auto* info_dict = std::get_if<dict>(&v)) {
                _val = std::make_shared<any_group_info>(legacy_group_info{oxenc::to_hex(k)});
                std::get<legacy_group_info>(*_val).load(*info_dict);
                return;
            }
        }
        ++*_it_legacy;
    }
}

bool UserGroups::iterator::operator==(const iterator& other) const {
    return _it_comm == other._it_comm && _it_legacy == other._it_legacy;
}

bool UserGroups::iterator::done() const {
    return !_it_comm && !_it_legacy;
}

UserGroups::iterator& UserGroups::iterator::operator++() {
    if (_it_comm)
        _it_comm->advance();
    else {
        assert(_it_legacy);
        ++*_it_legacy;
    }
    _load_val();
    return *this;
}

}  // namespace session::config

using namespace session::config;

extern "C" {
struct user_groups_iterator {
    void* _internals;
};
}

LIBSESSION_C_API
int user_groups_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    return c_wrapper_init<UserGroups>(conf, ed25519_secretkey_bytes, dumpstr, dumplen, error);
}

LIBSESSION_C_API bool user_groups_get_community(
        const config_object* conf,
        ugroups_community_info* comm,
        const char* base_url,
        const char* room) {
    try {
        if (auto c = unbox<UserGroups>(conf)->get_community(base_url, room)) {
            c->into(*comm);
            return true;
        }
    } catch (...) {
    }
    return false;
}
LIBSESSION_C_API bool user_groups_get_or_construct_community(
        const config_object* conf,
        ugroups_community_info* comm,
        const char* base_url,
        const char* room,
        unsigned const char* pubkey) {
    try {
        unbox<UserGroups>(conf)
                ->get_or_construct_community(base_url, room, ustring_view{pubkey, 32})
                .into(*comm);
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool user_groups_get_legacy_group(
        const config_object* conf, ugroups_legacy_group_info* group, const char* id) {
    try {
        if (auto c = unbox<UserGroups>(conf)->get_legacy_group(id)) {
            c->into(*group);
            return true;
        }
    } catch (...) {
    }
    return false;
}

LIBSESSION_C_API bool user_groups_get_or_construct_legacy_group(
        const config_object* conf, ugroups_legacy_group_info* group, const char* id) {
    try {
        unbox<UserGroups>(conf)->get_or_construct_legacy_group(id).into(*group);
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API void user_groups_set_community(
        config_object* conf, const ugroups_community_info* comm) {
    unbox<UserGroups>(conf)->set(community_info{*comm});
}
LIBSESSION_C_API void user_groups_set_legacy_group(
        config_object* conf, const ugroups_legacy_group_info* group) {
    unbox<UserGroups>(conf)->set(legacy_group_info{*group});
}

LIBSESSION_C_API bool user_groups_erase_community(
        config_object* conf, const char* base_url, const char* room) {
    try {
        return unbox<UserGroups>(conf)->erase_community(base_url, room);
    } catch (...) {
        return false;
    }
}
LIBSESSION_C_API bool user_groups_erase_legacy_group(config_object* conf, const char* group_id) {
    try {
        return unbox<UserGroups>(conf)->erase_legacy_group(group_id);
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API size_t user_groups_size(const config_object* conf) {
    return unbox<UserGroups>(conf)->size();
}
LIBSESSION_C_API size_t user_groups_size_communities(const config_object* conf) {
    return unbox<UserGroups>(conf)->size_communities();
}
LIBSESSION_C_API size_t user_groups_size_legacy_groups(const config_object* conf) {
    return unbox<UserGroups>(conf)->size_legacy_groups();
}

LIBSESSION_C_API user_groups_iterator* user_groups_iterator_new(const config_object* conf) {
    auto* it = new user_groups_iterator{};
    it->_internals = new UserGroups::iterator{unbox<UserGroups>(conf)->begin()};
    return it;
}

LIBSESSION_C_API user_groups_iterator* user_groups_iterator_new_communities(
        const config_object* conf) {
    auto* it = new user_groups_iterator{};
    it->_internals = new UserGroups::iterator{unbox<UserGroups>(conf)->begin_communities()};
    return it;
}
LIBSESSION_C_API user_groups_iterator* user_groups_iterator_new_legacy_groups(
        const config_object* conf) {
    auto* it = new user_groups_iterator{};
    it->_internals = new UserGroups::iterator{unbox<UserGroups>(conf)->begin_legacy_groups()};
    return it;
}

LIBSESSION_C_API void user_groups_iterator_free(user_groups_iterator* it) {
    delete static_cast<UserGroups::iterator*>(it->_internals);
    delete it;
}

LIBSESSION_C_API bool user_groups_iterator_done(user_groups_iterator* it) {
    auto& real = *static_cast<UserGroups::iterator*>(it->_internals);
    return real.done();
}

LIBSESSION_C_API void user_groups_iterator_advance(user_groups_iterator* it) {
    ++*static_cast<UserGroups::iterator*>(it->_internals);
}

namespace {
template <typename Cpp, typename C>
bool user_groups_it_is_impl(user_groups_iterator* it, C* c) {
    auto& convo = **static_cast<UserGroups::iterator*>(it->_internals);
    if (auto* d = std::get_if<Cpp>(&convo)) {
        d->into(*c);
        return true;
    }
    return false;
}
}  // namespace

LIBSESSION_C_API bool user_groups_it_is_community(
        user_groups_iterator* it, ugroups_community_info* c) {
    return user_groups_it_is_impl<community_info>(it, c);
}

LIBSESSION_C_API bool user_groups_it_is_legacy_group(
        user_groups_iterator* it, ugroups_legacy_group_info* g) {
    return user_groups_it_is_impl<legacy_group_info>(it, g);
}

LIBSESSION_C_API void user_groups_iterator_erase(config_object* conf, user_groups_iterator* it) {
    auto& real = *static_cast<UserGroups::iterator*>(it->_internals);
    real = unbox<UserGroups>(conf)->erase(real);
}
