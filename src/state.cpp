#include "session/state.hpp"

#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <nlohmann/json.hpp>
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
    auto info = std::make_unique<groups::Info>(pubkey, std::nullopt, std::nullopt, std::nullopt);
    auto members = std::make_unique<groups::Members>(pubkey, std::nullopt, std::nullopt, std::nullopt);
    auto keys = std::make_unique<groups::Keys>(
            user_sk, pubkey, std::nullopt, std::nullopt, *info, *members, std::nullopt);
    config_info = std::move(info);
    config_members = std::move(members);
    config_keys = std::move(keys);
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
    std::optional<session::state::State*> parent = this;
    config_contacts = std::make_unique<Contacts>(ed25519_secretkey, std::nullopt, parent);
    config_convo_info_volatile =
            std::make_unique<ConvoInfoVolatile>(ed25519_secretkey, std::nullopt, parent);
    config_user_groups = std::make_unique<UserGroups>(ed25519_secretkey, std::nullopt, parent);
    config_user_profile = std::make_unique<UserProfile>(ed25519_secretkey, std::nullopt, parent);
}

void State::load(
        Namespace namespace_, std::optional<std::string_view> pubkey_hex_, ustring_view dump) {
    std::optional<session::state::State*> parent = this;

    switch (namespace_) {
        case Namespace::Contacts:
            config_contacts =
                    std::make_unique<Contacts>(to_unsigned_sv({_user_sk.data(), 64}), dump, parent);
            return;

        case Namespace::ConvoInfoVolatile:
            config_convo_info_volatile = std::make_unique<ConvoInfoVolatile>(
                    to_unsigned_sv({_user_sk.data(), 64}), dump, parent);
            return;

        case Namespace::UserGroups:
            config_user_groups =
                    std::make_unique<UserGroups>(to_unsigned_sv({_user_sk.data(), 64}), dump, parent);
            return;

        case Namespace::UserProfile:
            config_user_profile =
                    std::make_unique<UserProfile>(to_unsigned_sv({_user_sk.data(), 64}), dump, parent);
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
    auto user_group_info = config_user_groups->get_group(*pubkey_hex_);

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
        _config_groups[pubkey_hex]->config_info =
                std::make_unique<groups::Info>(pubkey, group_ed25519_secretkey, dump, parent);
    else if (namespace_ == Namespace::GroupMembers)
        _config_groups[pubkey_hex]->config_members =
                std::make_unique<groups::Members>(pubkey, group_ed25519_secretkey, dump, parent);
    else if (namespace_ == Namespace::GroupKeys) {
        auto info = _config_groups[pubkey_hex]->config_info.get();
        auto members = _config_groups[pubkey_hex]->config_members.get();
        auto keys = std::make_unique<groups::Keys>(
                user_ed25519_secretkey, pubkey, pubkey, group_ed25519_secretkey, info, members, parent);

        _config_groups[pubkey_hex]->config_keys = std::move(keys);
    } else
        throw std::runtime_error{"Attempted to load unknown namespace"};
}

GroupConfigs* State::group_config(std::string_view pubkey_hex) {
    if (pubkey_hex.size() != 64)
        throw std::invalid_argument{"Invalid pubkey_hex: expected 64 bytes"};
    if (!_config_groups.count(pubkey_hex))
        throw std::runtime_error{
                "Attempted to merge group configs before for group with no config state"};

    return _config_groups[pubkey_hex].get();
}

std::vector<std::string> State::merge(
        std::optional<std::string_view> pubkey_hex, const std::vector<config_message>& configs) {
    if (configs.empty())
        return {};

    // Sort the namespaces based on the order they should be merged in to minimise conflicts between
    // different config messages
    auto sorted_configs = configs;
    std::sort(sorted_configs.begin(), sorted_configs.end(), [](const auto& a, const auto& b) {
        return namespace_merge_order(a.namespace_) < namespace_merge_order(b.namespace_);
    });

    std::vector<std::string> good_hashes;
    std::vector<std::pair<std::string, ustring_view>> pending_configs;

    for (size_t i = 0; i < sorted_configs.size(); ++i) {
        auto& config = sorted_configs[i];

        // If this is different from the last config, or it's a 'GroupKeys' config (GroupKeys
        // only support individual merging) then clear 'pending_configs' so we can prepare for
        // a new batch-merge
        if (config.namespace_ == Namespace::GroupKeys ||
            (i > 0 && config.namespace_ != sorted_configs[i - 1].namespace_))
            pending_configs.clear();

        pending_configs.emplace_back(config.hash, config.data);

        // If this is not a GroupKeys config, the last config or the next config is not in the same
        // namespace then go to the next loop so we can batch-merge the configs in a later loop
        if (config.namespace_ != Namespace::GroupKeys && i != (sorted_configs.size() - 1) &&
            config.namespace_ == sorted_configs[i + 1].namespace_)
            continue;

        // Process the previously grouped configs
        std::vector<std::string> merged_hashes;
        switch (config.namespace_) {
            case Namespace::Contacts:
                merged_hashes = config_contacts->merge(pending_configs);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());
                continue;

            case Namespace::ConvoInfoVolatile:
                merged_hashes = config_convo_info_volatile->merge(pending_configs);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());
                continue;

            case Namespace::UserGroups:
                merged_hashes = config_user_groups->merge(pending_configs);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());
                continue;

            case Namespace::UserProfile:
                merged_hashes = config_user_profile->merge(pending_configs);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());
                continue;

            default: break;
        }

        // Other namespaces are unique for a given pubkey_hex_
        if (!pubkey_hex)
            throw std::invalid_argument{
                    "Invalid pubkey_hex: pubkey_hex required for group config namespaces"};
        if (pubkey_hex->size() != 64)
            throw std::invalid_argument{"Invalid pubkey_hex: expected 64 bytes"};
        if (!_config_groups.count(*pubkey_hex))
            throw std::runtime_error{
                    "Attempted to merge group configs before for group with no config state"};

        auto info = _config_groups[*pubkey_hex]->config_info.get();
        auto members = _config_groups[*pubkey_hex]->config_members.get();

        if (config.namespace_ == Namespace::GroupInfo)
            merged_hashes = info->merge(pending_configs);
        else if (config.namespace_ == Namespace::GroupMembers)
            merged_hashes = members->merge(pending_configs);
        else if (config.namespace_ == Namespace::GroupKeys) {
            // GroupKeys doesn't support merging multiple messages at once so do them individually
            if (_config_groups[*pubkey_hex]->config_keys->load_key_message(
                        config.hash, config.data, config.timestamp_ms, *info, *members)) {
                good_hashes.emplace_back(config.hash);
            }
        } else
            throw std::runtime_error{"Attempted to merge from unknown namespace"};
    }

    return good_hashes;
}

void State::config_changed(std::optional<std::string_view> pubkey_hex) {
    throw std::runtime_error{"ASDASFSDFGSDF"};
    if (!send)
        return;

    bool needs_push = false;
    bool needs_dump = false;
    std::string target_pubkey;
    std::vector<config::ConfigBase*> configs;
    std::chrono::milliseconds timestamp =
            (std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch()) +
             network_offset);

    if (!pubkey_hex) {
        // Convert the _user_pk to the user's session ID
        std::array<unsigned char, 32> user_x_pk;

        if (0 != crypto_sign_ed25519_pk_to_curve25519(user_x_pk.data(), _user_pk.data()))
            throw std::runtime_error{"Sender ed25519 pubkey to x25519 pubkey conversion failed"};

        // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
        // the sender session ID
        target_pubkey.reserve(66);
        target_pubkey += "05";
        oxenc::to_hex(user_x_pk.begin(), user_x_pk.end(), std::back_inserter(target_pubkey));

        needs_push =
                (config_contacts->needs_push() || config_convo_info_volatile->needs_push() ||
                 config_user_groups->needs_push() || config_user_profile->needs_push());
        configs = {
                config_contacts.get(),
                config_convo_info_volatile.get(),
                config_user_groups.get(),
                config_user_profile.get()};
    } else {
        // Other namespaces are unique for a given pubkey_hex_
        if (!pubkey_hex)
            throw std::invalid_argument{
                    "Invalid pubkey_hex: pubkey_hex required for group config namespaces"};

        target_pubkey = *pubkey_hex;

        if (target_pubkey.size() != 64)
            throw std::invalid_argument{"Invalid pubkey_hex: expected 64 bytes"};
        if (!_config_groups.count(target_pubkey))
            throw std::runtime_error{"Change trigger in group configs with no state"};

        // Ensure we have the admin key for the group
        auto user_group_info = config_user_groups->get_group(target_pubkey);

        if (!user_group_info)
            throw std::runtime_error{"Unable to retrieve group from user_groups config"};

        // Only group admins can push group config changes
        needs_push =
                (!user_group_info->secretkey.empty() &&
                 (_config_groups[target_pubkey]->config_info->needs_push() ||
                  _config_groups[target_pubkey]->config_members->needs_push() ||
                  _config_groups[target_pubkey]->config_keys->pending_config()));
        configs = {
                _config_groups[target_pubkey]->config_info.get(),
                _config_groups[target_pubkey]->config_members.get()};
    }

    // Call the hook to perform a push if needed
    if (needs_push) {
        std::vector<nlohmann::json> requests;
        std::vector<std::string> obsolete_hashes;

        for (auto& config : configs) {
            auto [seqno, msg, obs] = config->push();

            for (auto hash : obs)
                obsolete_hashes.emplace_back(hash);

            // Ed25519 signature of `("store" || namespace || timestamp)`, where namespace and
            // `timestamp` are the base10 expression of the namespace and `timestamp` values
            std::array<unsigned char, 64> sig;
            ustring verification = to_unsigned("store") +
                                   static_cast<unsigned char>(config->storage_namespace()) +
                                   static_cast<unsigned char>(timestamp.count());

            if (0 != crypto_sign_ed25519_detached(
                             sig.data(),
                             nullptr,
                             verification.data(),
                             verification.size(),
                             _user_sk.data()))
                throw std::runtime_error{"Failed to sign; perhaps the secret key is invalid?"};

            nlohmann::json params{
                    {"namespace", static_cast<int>(config->storage_namespace())},
                    {"pubkey", target_pubkey},
                    {"ttl", config->default_ttl().count()},
                    {"timestamp", timestamp.count()},
                    {"data", oxenc::to_base64(msg)},
                    {"signature", oxenc::to_base64(sig.begin(), sig.end())},
            };

            // For user config storage we also need to add `pubkey_ed25519`
            if (!pubkey_hex)
                params["pubkey_ed25519"] = oxenc::to_hex(_user_pk.begin(), _user_pk.end());

            requests.emplace_back(params);
        }

        // GroupKeys needs special handling as it's not a `ConfigBase`
        if (pubkey_hex) {
            auto pending = _config_groups[target_pubkey]->config_keys->pending_config();

            if (pending) {
                // Ed25519 signature of `("store" || namespace || timestamp)`, where namespace and
                // `timestamp` are the base10 expression of the namespace and `timestamp` values
                std::array<unsigned char, 64> sig;
                ustring verification =
                        to_unsigned("store") +
                        static_cast<unsigned char>(
                                _config_groups[target_pubkey]->config_keys->storage_namespace()) +
                        static_cast<unsigned char>(timestamp.count());

                if (0 != crypto_sign_ed25519_detached(
                                 sig.data(),
                                 nullptr,
                                 verification.data(),
                                 verification.size(),
                                 _user_sk.data()))
                    throw std::runtime_error{"Failed to sign; perhaps the secret key is invalid?"};

                nlohmann::json params{
                        {"namespace",
                         _config_groups[target_pubkey]->config_keys->storage_namespace()},
                        {"pubkey", target_pubkey},
                        {"ttl", _config_groups[target_pubkey]->config_keys->default_ttl().count()},
                        {"timestamp", timestamp.count()},
                        {"data", oxenc::to_base64(*pending)},
                        {"signature", oxenc::to_base64(sig.begin(), sig.end())},
                };
                requests.emplace_back(params);
            }
        }

        // Sort the namespaces based on the order they should be stored in to minimise the chance
        // that config messages dependant on others are stored before their dependencies
        auto sorted_requests = requests;
        std::sort(sorted_requests.begin(), sorted_requests.end(), [](const auto& a, const auto& b) {
            return namespace_store_order(static_cast<Namespace>(a["namespace"])) <
                   namespace_store_order(static_cast<Namespace>(b["namespace"]));
        });

        nlohmann::json payload;

        for (auto& request : sorted_requests) {
            nlohmann::json request_json{{"method", "store"}, {"params", request}};
            payload["requests"].push_back(request_json);
        }

        // Also delete obsolete hashes
        if (!obsolete_hashes.empty()) {
            // Ed25519 signature of `("delete" || messages...)`
            std::array<unsigned char, 64> sig;
            ustring verification = to_unsigned("delete");

            for (auto& hash : obsolete_hashes)
                verification += to_unsigned_sv(hash);

            if (0 != crypto_sign_ed25519_detached(
                             sig.data(),
                             nullptr,
                             verification.data(),
                             verification.size(),
                             _user_sk.data()))
                throw std::runtime_error{"Failed to sign; perhaps the secret key is invalid?"};

            nlohmann::json params{
                    {"messages", obsolete_hashes},
                    {"pubkey", target_pubkey},
                    {"timestamp", timestamp.count()},
                    {"signature", oxenc::to_base64(sig.begin(), sig.end())},
            };

            // For user config storage we also need to add `pubkey_ed25519`
            if (!pubkey_hex)
                params["pubkey_ed25519"] = oxenc::to_hex(_user_pk.begin(), _user_pk.end());

            nlohmann::json request_json{{"method", "delete"}, {"params", params}};
            payload["requests"].push_back(request_json);
        }

        send(target_pubkey, payload);
}

ustring State::dump(bool full_dump) {
    oxenc::bt_dict_producer combined;

    // NOTE: the keys have to be in ascii-sorted order:
    if (full_dump || config_contacts->needs_dump())
        combined.append("contacts", session::from_unsigned_sv(config_contacts->dump()));

    if (full_dump || config_convo_info_volatile->needs_dump())
        combined.append(
                "convo_info_volatile",
                session::from_unsigned_sv(config_convo_info_volatile->dump()));

    if (full_dump || config_user_groups->needs_dump())
        combined.append("user_groups", session::from_unsigned_sv(config_user_groups->dump()));

    if (full_dump || config_user_profile->needs_dump())
        combined.append("user_profile", session::from_unsigned_sv(config_user_profile->dump()));

    // NOTE: `std::map` sorts keys in ascending order so can just add them in order
    if (_config_groups.size() > 0) {
        for (const auto& [key, config] : _config_groups) {
            if (full_dump || config->config_info->needs_dump() ||
                config->config_keys->needs_dump() || config->config_members->needs_dump()) {
                oxenc::bt_dict_producer group_combined = combined.append_dict(key);

                if (full_dump || config->config_info->needs_dump())
                    group_combined.append(
                            "info", session::from_unsigned_sv(config->config_info->dump()));

                if (full_dump || config->config_keys->needs_dump())
                    group_combined.append(
                            "keys", session::from_unsigned_sv(config->config_keys->dump()));

                if (full_dump || config->config_members->needs_dump())
                    group_combined.append(
                            "members", session::from_unsigned_sv(config->config_members->dump()));
            }
        }
    }

    auto to_dump = std::move(combined).str();

    return session::ustring{to_unsigned_sv(to_dump)};
}

ustring State::dump(config::Namespace namespace_, std::optional<std::string_view> pubkey_hex_) {
    switch (namespace_) {
        case Namespace::Contacts: return config_contacts->dump();
        case Namespace::ConvoInfoVolatile: return config_convo_info_volatile->dump();
        case Namespace::UserGroups: return config_user_groups->dump();
        case Namespace::UserProfile: return config_user_profile->dump();
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
        case Namespace::GroupInfo: return group_configs->config_info->dump();
        case Namespace::GroupMembers: return group_configs->config_members->dump();
        case Namespace::GroupKeys: return group_configs->config_keys->dump();
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

LIBSESSION_C_API void state_set_send_callback(
        state_object* state, void (*callback)(const char*, const unsigned char*, size_t)) {
    if (!callback)
        unbox(state).logger = nullptr;
    else {
        unbox(state).send = [callback](std::string pubkey, ustring data) {
            callback(pubkey.c_str(), data.data(), data.size());
        };
    }
}

LIBSESSION_C_API config_string_list* state_merge(
        state_object* state, const char* pubkey_hex_, state_config_message* configs, size_t count) {
    std::optional<std::string_view> pubkey_hex;
    if (pubkey_hex_)
        pubkey_hex.emplace(pubkey_hex_, 64);

    std::vector<config_message> confs;
    confs.reserve(count);

    for (size_t i = 0; i < count; i++)
        confs.emplace_back(
                static_cast<config::Namespace>(configs[i].namespace_),
                configs[i].hash,
                configs[i].timestamp_ms,
                ustring{configs[i].data, configs[i].datalen});

    return make_string_list(unbox(state).merge(pubkey_hex, confs));
}

LIBSESSION_C_API void state_dump(
        state_object* state, bool full_dump, unsigned char** out, size_t* outlen) {
    assert(out && outlen);
    auto data = unbox(state).dump(full_dump);
    *outlen = data.size();
    *out = static_cast<unsigned char*>(std::malloc(data.size()));
    std::memcpy(*out, data.data(), data.size());
}

LIBSESSION_C_API void state_dump_namespace(
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

LIBSESSION_C_API void state_set_logger(
        state_object* state, void (*callback)(config_log_level, const char*, void*), void* ctx) {
    if (!callback)
        unbox(state).logger = nullptr;
    else {
        unbox(state).config_contacts->logger = [callback, ctx](
                                                       session::config::LogLevel lvl,
                                                       std::string msg) {
            callback(static_cast<config_log_level>(static_cast<int>(lvl)), msg.c_str(), ctx);
        };
        unbox(state).config_convo_info_volatile->logger = [callback, ctx](
                                                                  session::config::LogLevel lvl,
                                                                  std::string msg) {
            callback(static_cast<config_log_level>(static_cast<int>(lvl)), msg.c_str(), ctx);
        };
        unbox(state).config_user_groups->logger = [callback, ctx](
                                                          session::config::LogLevel lvl,
                                                          std::string msg) {
            callback(static_cast<config_log_level>(static_cast<int>(lvl)), msg.c_str(), ctx);
        };
        unbox(state).config_user_profile->logger = [callback, ctx](
                                                           session::config::LogLevel lvl,
                                                           std::string msg) {
            callback(static_cast<config_log_level>(static_cast<int>(lvl)), msg.c_str(), ctx);
        };
    }
}

}  // extern "C"
