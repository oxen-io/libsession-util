#include "session/state.hpp"

#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include <stdexcept>
#include <string>

#include "config/internal.hpp"
#include "session/config/base.hpp"
#include "session/config/contacts.hpp"
#include "session/config/convo_info_volatile.hpp"
#include "session/config/namespaces.h"
#include "session/config/namespaces.hpp"
#include "session/config/user_groups.hpp"
#include "session/config/user_profile.hpp"
#include "session/export.h"
#include "session/state.h"
#include "session/util.hpp"

using namespace std::literals;
using namespace session::config;

namespace session::state {

GroupConfigs::GroupConfigs(ustring_view pubkey, ustring_view user_sk) {
    auto info = std::make_unique<groups::Info>(pubkey, std::nullopt, std::nullopt);
    auto members = std::make_unique<groups::Members>(pubkey, std::nullopt, std::nullopt);
    auto keys = std::make_unique<groups::Keys>(
            user_sk, pubkey, std::nullopt, std::nullopt, *info, *members);
    _config_info = std::move(info);
    _config_members = std::move(members);
    _config_keys = std::move(keys);
}

State::State(ustring_view ed25519_secretkey) {
    if (sodium_init() == -1)
        throw std::runtime_error{"libsodium initialization failed!"};
    if (ed25519_secretkey.size() != 64)
        throw std::invalid_argument{"Invalid ed25519_secretkey: expected 64 bytes"};

    _user_sk.reset(64);
    std::memcpy(_user_sk.data(), ed25519_secretkey.data(), ed25519_secretkey.size());
    crypto_sign_ed25519_sk_to_pk(_user_pk.data(), _user_sk.data());

    // Initialise empty config states for the standard config types
    _config_contacts = std::make_unique<Contacts>(ed25519_secretkey, std::nullopt);
    _config_convo_info_volatile =
            std::make_unique<ConvoInfoVolatile>(ed25519_secretkey, std::nullopt);
    _config_user_groups = std::make_unique<UserGroups>(ed25519_secretkey, std::nullopt);
    _config_user_profile = std::make_unique<UserProfile>(ed25519_secretkey, std::nullopt);
}

void State::load(
        Namespace namespace_, std::optional<std::string_view> pubkey_hex_, ustring_view dump) {
    switch (namespace_) {
        case Namespace::Contacts:
            _config_contacts =
                    std::make_unique<Contacts>(to_unsigned_sv({_user_sk.data(), 64}), dump);
            return;

        case Namespace::ConvoInfoVolatile:
            _config_convo_info_volatile = std::make_unique<ConvoInfoVolatile>(
                    to_unsigned_sv({_user_sk.data(), 64}), dump);
            return;

        case Namespace::UserGroups:
            _config_user_groups =
                    std::make_unique<UserGroups>(to_unsigned_sv({_user_sk.data(), 64}), dump);
            return;

        case Namespace::UserProfile:
            _config_user_profile =
                    std::make_unique<UserProfile>(to_unsigned_sv({_user_sk.data(), 64}), dump);
            return;

        default: break;
    }

    // Other namespaces are unique for a given pubkey_hex_
    if (!pubkey_hex_)
        throw std::invalid_argument{
                "Invalid pubkey_hex: pubkey_hex required for group config namespaces"};
    if (pubkey_hex_->size() != 64)
        throw std::invalid_argument{"Invalid pubkey_hex: expected 64 bytes"};

    // Retrieve any keys for the group
    auto user_group_info = _config_user_groups->get_group(*pubkey_hex_);

    if (!user_group_info)
        throw std::runtime_error{"Unable to retrieve group from user_groups config"};

    std::string_view pubkey_hex = *pubkey_hex_;
    ustring_view pubkey = to_unsigned_sv(session_id_to_bytes(*pubkey_hex_, "03"));
    ustring_view user_ed25519_secretkey = {_user_sk.data(), 64};
    std::optional<ustring_view> opt_dump = dump;
    std::optional<ustring_view> group_ed25519_secretkey;

    if (!user_group_info.value().secretkey.empty())
        group_ed25519_secretkey = {user_group_info.value().secretkey.data(), 64};

    // Create a fresh `GroupConfigs` state
    if (!_config_groups.count(pubkey_hex)) {
        if (namespace_ == Namespace::GroupKeys)
            throw std::runtime_error{
                    "Attempted to load groups_keys config before groups_info or groups_members "
                    "configs"};

        _config_groups[pubkey_hex] = std::make_unique<GroupConfigs>(pubkey, user_ed25519_secretkey);
    }

    // Reload the specified namespace with the dump
    if (namespace_ == Namespace::GroupInfo)
        _config_groups[pubkey_hex]->_config_info =
                std::make_unique<groups::Info>(pubkey, group_ed25519_secretkey, dump);
    else if (namespace_ == Namespace::GroupMembers)
        _config_groups[pubkey_hex]->_config_members =
                std::make_unique<groups::Members>(pubkey, group_ed25519_secretkey, dump);
    else if (namespace_ == Namespace::GroupKeys) {
        auto info = _config_groups[pubkey_hex]->_config_info.get();
        auto members = _config_groups[pubkey_hex]->_config_members.get();
        auto keys = std::make_unique<groups::Keys>(
                user_ed25519_secretkey, pubkey, pubkey, group_ed25519_secretkey, info, members);

        _config_groups[pubkey_hex]->_config_keys = std::move(keys);
    } else
        throw std::runtime_error{"Attempted to load unknown namespace"};
}

ustring State::dump(bool full_dump) {
    oxenc::bt_dict_producer combined;

    // NOTE: the keys have to be in ascii-sorted order:
    if (full_dump || _config_contacts->needs_dump())
        combined.append("contacts", session::from_unsigned_sv(_config_contacts->dump()));

    if (full_dump || _config_convo_info_volatile->needs_dump())
        combined.append(
                "convo_info_volatile",
                session::from_unsigned_sv(_config_convo_info_volatile->dump()));

    if (full_dump || _config_user_groups->needs_dump())
        combined.append("user_groups", session::from_unsigned_sv(_config_user_groups->dump()));

    if (full_dump || _config_user_profile->needs_dump())
        combined.append("user_profile", session::from_unsigned_sv(_config_user_profile->dump()));

    // NOTE: `std::map` sorts keys in ascending order so can just add them in order
    if (_config_groups.size() > 0) {
        for (const auto& [key, config] : _config_groups) {
            if (full_dump || config->_config_info->needs_dump() ||
                config->_config_keys->needs_dump() || config->_config_members->needs_dump()) {
                oxenc::bt_dict_producer group_combined = combined.append_dict(key);

                if (full_dump || config->_config_info->needs_dump())
                    group_combined.append(
                            "info", session::from_unsigned_sv(config->_config_info->dump()));

                if (full_dump || config->_config_keys->needs_dump())
                    group_combined.append(
                            "keys", session::from_unsigned_sv(config->_config_keys->dump()));

                if (full_dump || config->_config_members->needs_dump())
                    group_combined.append(
                            "members", session::from_unsigned_sv(config->_config_members->dump()));
            }
        }
    }

    auto to_dump = std::move(combined).str();

    return session::ustring{to_unsigned_sv(to_dump)};
}

ustring State::dump(config::Namespace namespace_, std::optional<std::string_view> pubkey_hex_) {
    switch (namespace_) {
        case Namespace::Contacts: return _config_contacts->dump();
        case Namespace::ConvoInfoVolatile: return _config_convo_info_volatile->dump();
        case Namespace::UserGroups: return _config_user_groups->dump();
        case Namespace::UserProfile: return _config_user_profile->dump();
        default: break;
    }

    // Other namespaces are unique for a given pubkey_hex_
    if (!pubkey_hex_)
        throw std::invalid_argument{
                "Invalid pubkey_hex: pubkey_hex required for group config namespaces"};
    if (pubkey_hex_->size() != 64)
        throw std::invalid_argument{"Invalid pubkey_hex: expected 64 bytes"};
    if (!_config_groups.count(*pubkey_hex_))
        throw std::runtime_error{"Unable to retrieve group"};

    // Retrieve the group configs for this pubkey
    auto group_configs = _config_groups[*pubkey_hex_].get();

    switch (namespace_) {
        case Namespace::GroupInfo: return group_configs->_config_info->dump();
        case Namespace::GroupMembers: return group_configs->_config_members->dump();
        case Namespace::GroupKeys: return group_configs->_config_keys->dump();
        default: throw std::runtime_error{"Attempted to load unknown namespace"};
    }
}

}  // namespace session::state

using namespace session;
using namespace session::state;

namespace {
State& unbox(state_object* state) {
    assert(state && state->internals);
    return *static_cast<State*>(state->internals);
}
const State& unbox(const state_object* state) {
    assert(state && state->internals);
    return *static_cast<const State*>(state->internals);
}

bool set_error(state_object* state, std::string_view e) {
    if (e.size() > 255)
        e.remove_suffix(e.size() - 255);
    std::memcpy(state->_error_buf, e.data(), e.size());
    state->_error_buf[e.size()] = 0;
    state->last_error = state->_error_buf;
    return false;
}
}  // namespace

extern "C" {

LIBSESSION_EXPORT void state_free(state_object* state) {
    delete state;
}

LIBSESSION_C_API bool state_create(state_object** state, char* error) {
    try {
        auto s = std::make_unique<session::state::State>();
        auto s_object = std::make_unique<state_object>();

        s_object->internals = s.release();
        s_object->last_error = nullptr;
        *state = s_object.release();
        return true;
    } catch (const std::exception& e) {
        if (error) {
            std::string msg = e.what();
            if (msg.size() > 255)
                msg.resize(255);
            std::memcpy(error, msg.c_str(), msg.size() + 1);
        }
        return false;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool state_init(
        state_object** state, const unsigned char* ed25519_secretkey_bytes, char* error) {
    try {
        auto s = std::make_unique<session::state::State>(
                session::ustring_view{ed25519_secretkey_bytes, 64});
        auto s_object = std::make_unique<state_object>();

        s_object->internals = s.release();
        s_object->last_error = nullptr;
        *state = s_object.release();
        return true;
    } catch (const std::exception& e) {
        if (error) {
            std::string msg = e.what();
            if (msg.size() > 255)
                msg.resize(255);
            std::memcpy(error, msg.c_str(), msg.size() + 1);
        }
        return false;
    }
}

LIBSESSION_C_API bool state_load(
        state_object* state,
        NAMESPACE namespace_,
        const char* pubkey_hex_,
        const unsigned char* dump,
        size_t dumplen) {
    assert(state && dump && dumplen);

    session::ustring_view dumped{dump, dumplen};
    std::optional<std::string_view> pubkey_hex;
    if (pubkey_hex_)
        pubkey_hex.emplace(pubkey_hex_, 64);

    try {
        auto target_namespace = static_cast<Namespace>(namespace_);

        unbox(state).load(target_namespace, pubkey_hex, dumped);
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_EXPORT void state_dump(
        state_object* state, bool full_dump, unsigned char** out, size_t* outlen) {
    assert(out && outlen);
    auto data = unbox(state).dump(full_dump);
    *outlen = data.size();
    *out = static_cast<unsigned char*>(std::malloc(data.size()));
    std::memcpy(*out, data.data(), data.size());
}

LIBSESSION_EXPORT void state_dump_namespace(
        state_object* state,
        NAMESPACE namespace_,
        const char* pubkey_hex_,
        unsigned char** out,
        size_t* outlen) {
    assert(out && outlen);

    std::optional<std::string_view> pubkey_hex;
    if (pubkey_hex_)
        pubkey_hex.emplace(pubkey_hex_, 64);

    auto target_namespace = static_cast<Namespace>(namespace_);
    auto data = unbox(state).dump(target_namespace, pubkey_hex);
    *outlen = data.size();
    *out = static_cast<unsigned char*>(std::malloc(data.size()));
    std::memcpy(*out, data.data(), data.size());
}

// User Profile Functions

LIBSESSION_C_API const char* state_get_profile_name(const state_object* state) {
    if (auto s = unbox(state).get_profile_name())
        return s->data();
    return nullptr;
}

LIBSESSION_C_API bool state_set_profile_name(state_object* state, const char* name) {
    try {
        unbox(state).set_profile_name(name);
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API user_profile_pic state_get_profile_pic(const state_object* state) {
    user_profile_pic p;
    if (auto pic = unbox(state).get_profile_pic(); pic) {
        copy_c_str(p.url, pic.url);
        std::memcpy(p.key, pic.key.data(), 32);
    } else {
        p.url[0] = 0;
    }
    return p;
}

LIBSESSION_C_API bool state_set_profile_pic(state_object* state, user_profile_pic pic) {
    std::string_view url{pic.url};
    ustring_view key;
    if (!url.empty())
        key = {pic.key, 32};

    try {
        unbox(state).set_profile_pic(url, key);
        return true;
    } catch (const std::exception& e) {
        return set_error(state, e.what());
    }
}

LIBSESSION_C_API int state_get_profile_blinded_msgreqs(const state_object* state) {
    if (auto opt = unbox(state).get_profile_blinded_msgreqs())
        return static_cast<int>(*opt);
    return -1;
}

LIBSESSION_C_API void state_set_profile_blinded_msgreqs(state_object* state, int enabled) {
    std::optional<bool> val;
    if (enabled >= 0)
        val = static_cast<bool>(enabled);
    unbox(state).set_profile_blinded_msgreqs(std::move(val));
}

}  // extern "C"
