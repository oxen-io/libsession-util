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
    auto members =
            std::make_unique<groups::Members>(pubkey, std::nullopt, std::nullopt, std::nullopt);
    auto keys = std::make_unique<groups::Keys>(
            user_sk, pubkey, std::nullopt, std::nullopt, *info, *members, std::nullopt);
    config_info = std::move(info);
    config_members = std::move(members);
    config_keys = std::move(keys);
}

State::State(ustring_view ed25519_secretkey, std::vector<namespaced_dump> dumps) {
    if (sodium_init() == -1)
        throw std::runtime_error{"libsodium initialization failed!"};
    if (ed25519_secretkey.size() != 64)
        throw std::invalid_argument{"Invalid ed25519_secretkey: expected 64 bytes"};

    std::memcpy(_user_sk.data(), ed25519_secretkey.data(), ed25519_secretkey.size());
    crypto_sign_ed25519_sk_to_pk(_user_pk.data(), _user_sk.data());

    // Load in the dumps
    auto sorted_dumps = dumps;
    std::sort(sorted_dumps.begin(), sorted_dumps.end(), [](const auto& a, const auto& b) {
        return namespace_load_order(a.namespace_) < namespace_load_order(b.namespace_);
    });

    for (auto dump : sorted_dumps) {
        load(dump.namespace_, dump.pubkey_hex, dump.data);
    }

    // Initialise empty config states for any missing required config types
    std::optional<session::state::State*> parent = this;

    if (!config_contacts)
        config_contacts = std::make_unique<Contacts>(ed25519_secretkey, std::nullopt, parent);

    if (!config_convo_info_volatile)
        config_convo_info_volatile =
                std::make_unique<ConvoInfoVolatile>(ed25519_secretkey, std::nullopt, parent);

    if (!config_user_groups)
        config_user_groups = std::make_unique<UserGroups>(ed25519_secretkey, std::nullopt, parent);

    if (!config_user_profile)
        config_user_profile =
                std::make_unique<UserProfile>(ed25519_secretkey, std::nullopt, parent);
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
            config_user_groups = std::make_unique<UserGroups>(
                    to_unsigned_sv({_user_sk.data(), 64}), dump, parent);
            return;

        case Namespace::UserProfile:
            config_user_profile = std::make_unique<UserProfile>(
                    to_unsigned_sv({_user_sk.data(), 64}), dump, parent);
            return;

        default: break;
    }

    // Other namespaces are unique for a given pubkey_hex_
    if (!pubkey_hex_)
        throw std::invalid_argument{
                "load: Invalid pubkey_hex - required for group config namespaces"};
    if (pubkey_hex_->size() != 66)
        throw std::invalid_argument{"load: Invalid pubkey_hex - expected 66 bytes"};

    // Retrieve any keys for the group
    std::string_view pubkey_hex = *pubkey_hex_;
    auto user_group_info = config_user_groups->get_group(pubkey_hex);

    if (!user_group_info)
        throw std::runtime_error{
                "Unable to retrieve group " + std::string(pubkey_hex) + " from user_groups config"};

    auto pubkey = session_id_pk(pubkey_hex, "03");
    ustring_view pubkey_sv = to_unsigned_sv(pubkey);
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

        _config_groups[pubkey_hex] =
                std::make_unique<GroupConfigs>(pubkey_sv, user_ed25519_secretkey);
    }

    // Reload the specified namespace with the dump
    if (namespace_ == Namespace::GroupInfo)
        _config_groups[pubkey_hex]->config_info =
                std::make_unique<groups::Info>(pubkey_sv, group_ed25519_secretkey, dump, parent);
    else if (namespace_ == Namespace::GroupMembers)
        _config_groups[pubkey_hex]->config_members =
                std::make_unique<groups::Members>(pubkey_sv, group_ed25519_secretkey, dump, parent);
    else if (namespace_ == Namespace::GroupKeys) {
        auto info = _config_groups[pubkey_hex]->config_info.get();
        auto members = _config_groups[pubkey_hex]->config_members.get();
        auto keys = std::make_unique<groups::Keys>(
                user_ed25519_secretkey,
                pubkey_sv,
                group_ed25519_secretkey,
                dump,
                info,
                members,
                parent);

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

void State::suppress_hooks_start(bool send, bool store, std::string_view pubkey_hex) {
    log(LogLevel::debug,
        "suppress_hooks_start: " + std::string(pubkey_hex) + "(send: " + bool_to_string(send) +
                ", store: " + bool_to_string(store) + ")");
    _open_suppressions[pubkey_hex] = {send, store};
}

void State::suppress_hooks_stop(bool send, bool store, std::string_view pubkey_hex) {
    log(LogLevel::debug,
        "suppress_hooks_stop: " + std::string(pubkey_hex) + "(send: " + bool_to_string(send) +
                ", store: " + bool_to_string(store) + ")");

    // If `_open_suppressions` doesn't contain a value it'll default to {false, false}
    if ((send && store) || (send && !_open_suppressions[pubkey_hex].second) ||
        (store && !_open_suppressions[pubkey_hex].first))
        _open_suppressions.erase(pubkey_hex);
    else if (send)
        _open_suppressions[pubkey_hex] = {false, _open_suppressions[pubkey_hex].second};
    else if (store)
        _open_suppressions[pubkey_hex] = {_open_suppressions[pubkey_hex].first, false};

    // Trigger the config change hooks if needed with the relevant pubkey information
    if (pubkey_hex.substr(0, 2) == "05")
        config_changed(std::nullopt);  // User config storage
    else if (pubkey_hex.empty()) {
        // Update all configs (as it's possible this change affected multiple configs)
        config_changed(std::nullopt);  // User config storage

        for (auto& [key, val] : _config_groups) {
            config_changed(key);  // Group config storage
        }
    } else
        config_changed(pubkey_hex);  // Key-specific configs
}

void State::config_changed(std::optional<std::string_view> pubkey_hex) {
    std::string target_pubkey_hex;

    if (!pubkey_hex) {
        // Convert the _user_pk to the user's session ID
        std::array<unsigned char, 32> user_x_pk;

        if (0 != crypto_sign_ed25519_pk_to_curve25519(user_x_pk.data(), _user_pk.data()))
            throw std::runtime_error{"Sender ed25519 pubkey to x25519 pubkey conversion failed"};

        // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
        // the sender session ID
        target_pubkey_hex.reserve(66);
        target_pubkey_hex += "05";
        oxenc::to_hex(user_x_pk.begin(), user_x_pk.end(), std::back_inserter(target_pubkey_hex));
    } else
        target_pubkey_hex = *pubkey_hex;

    // Check if there both `send` and `store` hooks are suppressed (and if so ignore this change)
    std::pair<bool, bool> suppressions =
            (_open_suppressions.count(target_pubkey_hex) ? _open_suppressions[target_pubkey_hex]
                                                         : _open_suppressions[""]);

    if (suppressions.first && suppressions.second) {
        log(LogLevel::debug, "config_changed: Ignoring due to hooks being suppressed");
        return;
    }

    std::string info_title = "User configs";
    bool needs_push = false;
    bool needs_dump = false;
    std::vector<config::ConfigBase*> configs;
    std::chrono::milliseconds timestamp =
            (std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch()) +
             network_offset);

    if (!pubkey_hex) {
        needs_push =
                (!suppressions.first &&
                 (config_contacts->needs_push() || config_convo_info_volatile->needs_push() ||
                  config_user_groups->needs_push() || config_user_profile->needs_push()));
        needs_dump =
                (!suppressions.second &&
                 (config_contacts->needs_dump() || config_convo_info_volatile->needs_dump() ||
                  config_user_groups->needs_dump() || config_user_profile->needs_dump()));
        configs = {
                config_contacts.get(),
                config_convo_info_volatile.get(),
                config_user_groups.get(),
                config_user_profile.get()};
    } else {
        // Other namespaces are unique for a given pubkey_hex_
        if (!pubkey_hex)
            throw std::invalid_argument{
                    "config_changed: Invalid pubkey_hex - required for group config namespaces"};
        if (target_pubkey_hex.size() != 66)
            throw std::invalid_argument{"config_changed: Invalid pubkey_hex - expected 66 bytes"};
        if (!_config_groups.count(target_pubkey_hex))
            throw std::runtime_error{
                    "config_changed: Change trigger in group configs with no state"};

        // Ensure we have the admin key for the group
        auto user_group_info = config_user_groups->get_group(target_pubkey_hex);

        if (!user_group_info)
            throw std::runtime_error{
                    "config_changed: Unable to retrieve group " + target_pubkey_hex +
                    " from user_groups config"};

        // Only group admins can push group config changes
        needs_push =
                (!suppressions.first && !user_group_info->secretkey.empty() &&
                 (_config_groups[target_pubkey_hex]->config_info->needs_push() ||
                  _config_groups[target_pubkey_hex]->config_members->needs_push() ||
                  _config_groups[target_pubkey_hex]->config_keys->pending_config()));
        needs_dump =
                (!suppressions.second &&
                 (_config_groups[target_pubkey_hex]->config_info->needs_dump() ||
                  _config_groups[target_pubkey_hex]->config_members->needs_dump() ||
                  _config_groups[target_pubkey_hex]->config_keys->needs_dump()));
        configs = {
                _config_groups[target_pubkey_hex]->config_info.get(),
                _config_groups[target_pubkey_hex]->config_members.get()};
        info_title = "Group configs for " + target_pubkey_hex;
    }

    std::string send_info =
            (suppressions.first ? "send suppressed"
                                : ("needs send: " + bool_to_string(needs_push)));
    std::string store_info =
            (suppressions.second ? "store suppressed"
                                 : ("needs store: " + bool_to_string(needs_dump)));
    log(LogLevel::debug,
        "config_changed: " + info_title + " (" + send_info + ", " + store_info + ")");

    // Call the hook to store the dump if needed
    if (_store && needs_dump && !suppressions.second) {
        for (auto& config : configs) {
            if (!config->needs_dump())
                continue;
            log(LogLevel::debug,
                "config_changed: call 'store' for namespace: " +
                        std::to_string(static_cast<int>(config->storage_namespace())));
            _store(config->storage_namespace(),
                   target_pubkey_hex,
                   timestamp.count(),
                   config->dump());
        }

        // GroupKeys needs special handling as it's not a `ConfigBase`
        if (pubkey_hex && _config_groups[target_pubkey_hex]->config_keys->needs_dump()) {
            log(LogLevel::debug,
                "config_changed: Group Keys config for " + target_pubkey_hex + " needs_dump");
            auto keys_config = _config_groups[target_pubkey_hex]->config_keys.get();

            _store(keys_config->storage_namespace(),
                   target_pubkey_hex,
                   timestamp.count(),
                   keys_config->dump());
        }
    }

    // Call the hook to perform a push if needed
    if (_send && needs_push && !suppressions.first) {
        std::vector<seqno_t> seqnos;
        std::vector<nlohmann::json> requests;
        std::vector<std::string> obsolete_hashes;

        for (auto& config : configs) {
            if (!config->needs_push())
                continue;
            log(LogLevel::debug,
                "config_changed: generate 'send' request for namespace: " +
                        std::to_string(static_cast<int>(config->storage_namespace())));
            auto [seqno, msg, obs] = config->push();

            for (auto hash : obs)
                obsolete_hashes.emplace_back(hash);

            // Ed25519 signature of `("store" || namespace || timestamp)`, where namespace and
            // `timestamp` are the base10 expression of the namespace and `timestamp` values
            std::array<unsigned char, 64> sig;
            ustring verification = to_unsigned("store");
            verification +=
                    to_unsigned_sv(std::to_string(static_cast<int>(config->storage_namespace())));
            verification += to_unsigned_sv(std::to_string(timestamp.count()));

            if (0 != crypto_sign_ed25519_detached(
                             sig.data(),
                             nullptr,
                             verification.data(),
                             verification.size(),
                             _user_sk.data()))
                throw std::runtime_error{
                        "config_changed: Failed to sign; perhaps the secret key is invalid?"};

            nlohmann::json params{
                    {"namespace", static_cast<int>(config->storage_namespace())},
                    {"pubkey", target_pubkey_hex},
                    {"ttl", config->default_ttl().count()},
                    {"timestamp", timestamp.count()},
                    {"data", oxenc::to_base64(msg)},
                    {"signature", oxenc::to_base64(sig.begin(), sig.end())},
            };

            // For user config storage we also need to add `pubkey_ed25519`
            if (!pubkey_hex)
                params["pubkey_ed25519"] = oxenc::to_hex(_user_pk.begin(), _user_pk.end());

            seqnos.emplace_back(seqno);
            requests.emplace_back(params);
        }

        // GroupKeys needs special handling as it's not a `ConfigBase`
        if (pubkey_hex) {
            auto pending = _config_groups[target_pubkey_hex]->config_keys->pending_config();

            if (pending) {
                log(LogLevel::debug,
                    "config_changed: generate 'send' request for group keys " + target_pubkey_hex);
                // Ed25519 signature of `("store" || namespace || timestamp)`, where namespace and
                // `timestamp` are the base10 expression of the namespace and `timestamp` values
                std::array<unsigned char, 64> sig;
                ustring verification =
                        to_unsigned("store") +
                        static_cast<unsigned char>(_config_groups[target_pubkey_hex]
                                                           ->config_keys->storage_namespace()) +
                        static_cast<unsigned char>(timestamp.count());

                if (0 != crypto_sign_ed25519_detached(
                                 sig.data(),
                                 nullptr,
                                 verification.data(),
                                 verification.size(),
                                 _user_sk.data()))
                    throw std::runtime_error{
                            "config_changed: Failed to sign; perhaps the secret key is invalid?"};

                nlohmann::json params{
                        {"namespace",
                         _config_groups[target_pubkey_hex]->config_keys->storage_namespace()},
                        {"pubkey", target_pubkey_hex},
                        {"ttl",
                         _config_groups[target_pubkey_hex]->config_keys->default_ttl().count()},
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

        nlohmann::json sequence_params;

        for (auto& request : sorted_requests) {
            nlohmann::json request_json{{"method", "store"}, {"params", request}};
            sequence_params["requests"].push_back(request_json);
        }

        // Also delete obsolete hashes
        if (!obsolete_hashes.empty()) {
            // Ed25519 signature of `("delete" || messages...)`
            std::array<unsigned char, 64> sig;
            ustring verification = to_unsigned("delete");
            log(LogLevel::debug, "config_changed: has obsolete hashes");
            for (auto& hash : obsolete_hashes)
                verification += to_unsigned_sv(hash);

            if (0 != crypto_sign_ed25519_detached(
                             sig.data(),
                             nullptr,
                             verification.data(),
                             verification.size(),
                             _user_sk.data()))
                throw std::runtime_error{
                        "config_changed: Failed to sign; perhaps the secret key is invalid?"};

            nlohmann::json params{
                    {"messages", obsolete_hashes},
                    {"pubkey", target_pubkey_hex},
                    {"signature", oxenc::to_base64(sig.begin(), sig.end())},
            };

            // For user config storage we also need to add `pubkey_ed25519`
            if (!pubkey_hex)
                params["pubkey_ed25519"] = oxenc::to_hex(_user_pk.begin(), _user_pk.end());

            nlohmann::json request_json{{"method", "delete"}, {"params", params}};
            sequence_params["requests"].push_back(request_json);
        }
        log(LogLevel::debug, "config_changed: Call 'send'");
        nlohmann::json payload{{"method", "sequence"}, {"params", sequence_params}};
        auto payload_dump = payload.dump();
        _send(target_pubkey_hex, seqnos, {to_unsigned(payload_dump.data()), payload_dump.size()});
    }
    log(LogLevel::debug, "config_changed: Complete");
}

std::vector<std::string> State::merge(
        std::optional<std::string_view> pubkey_hex, const std::vector<config_message>& configs) {
    log(LogLevel::debug, "merge: Called with " + std::to_string(configs.size()) + " configs");
    if (configs.empty())
        return {};

    // Sort the namespaces based on the order they should be merged in to minimise conflicts between
    // different config messages
    auto sorted_configs = configs;
    std::sort(sorted_configs.begin(), sorted_configs.end(), [](const auto& a, const auto& b) {
        return namespace_merge_order(a.namespace_) < namespace_merge_order(b.namespace_);
    });

    bool is_group_merge = false;
    std::vector<std::string> good_hashes;
    std::vector<std::pair<std::string, ustring_view>> pending_configs;
    std::string target_pubkey_hex;

    if (!pubkey_hex) {
        // Convert the _user_pk to the user's session ID
        std::array<unsigned char, 32> user_x_pk;

        if (0 != crypto_sign_ed25519_pk_to_curve25519(user_x_pk.data(), _user_pk.data()))
            throw std::runtime_error{
                    "merge: Sender ed25519 pubkey to x25519 pubkey conversion failed"};

        // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
        // the sender session ID
        target_pubkey_hex.reserve(66);
        target_pubkey_hex += "05";
        oxenc::to_hex(user_x_pk.begin(), user_x_pk.end(), std::back_inserter(target_pubkey_hex));
    } else
        target_pubkey_hex = *pubkey_hex;

    // Suppress triggering the `send` hook until the merge is complete
    suppress_hooks_start(true, false, target_pubkey_hex);

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
                log(LogLevel::debug, "merge: Merging CONTACTS config");
                merged_hashes = config_contacts->merge(pending_configs);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());
                continue;

            case Namespace::ConvoInfoVolatile:
                log(LogLevel::debug, "merge: Merging CONVO_INFO_VOLATILE config");
                merged_hashes = config_convo_info_volatile->merge(pending_configs);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());
                continue;

            case Namespace::UserGroups:
                log(LogLevel::debug, "merge: Merging USER_GROUPS config");
                merged_hashes = config_user_groups->merge(pending_configs);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());
                continue;

            case Namespace::UserProfile:
                log(LogLevel::debug, "merge: Merging USER_PROFILE config");
                merged_hashes = config_user_profile->merge(pending_configs);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());
                continue;

            default: break;
        }

        // Other namespaces are unique for a given pubkey_hex_
        if (!pubkey_hex)
            throw std::invalid_argument{
                    "merge: Invalid pubkey_hex - required for group config namespaces"};
        if (target_pubkey_hex.size() != 66)
            throw std::invalid_argument{"merge: Invalid pubkey_hex - expected 66 bytes"};
        if (!_config_groups.count(target_pubkey_hex))
            throw std::runtime_error{
                    "merge: Attempted to merge group configs before for group with no config "
                    "state"};

        auto info = _config_groups[target_pubkey_hex]->config_info.get();
        auto members = _config_groups[target_pubkey_hex]->config_members.get();
        is_group_merge = true;

        if (config.namespace_ == Namespace::GroupInfo) {
            log(LogLevel::debug,
                "merge: Merging GROUP_INFO config for: " + std::string(target_pubkey_hex));
            merged_hashes = info->merge(pending_configs);
        } else if (config.namespace_ == Namespace::GroupMembers) {
            log(LogLevel::debug,
                "merge: Merging GROUP_MEMBERS config for: " + std::string(target_pubkey_hex));
            merged_hashes = members->merge(pending_configs);
        } else if (config.namespace_ == Namespace::GroupKeys) {
            log(LogLevel::debug,
                "merge: Merging GROUP_KEYS config for: " + std::string(target_pubkey_hex));
            // GroupKeys doesn't support merging multiple messages at once so do them individually
            if (_config_groups[target_pubkey_hex]->config_keys->load_key_message(
                        config.hash, config.data, config.timestamp_ms, *info, *members)) {
                good_hashes.emplace_back(config.hash);
            }
        } else
            throw std::runtime_error{"merge: Attempted to merge from unknown namespace"};
    }

    // Now that all of the merges have been completed we stop suppressing the `send` hook which
    // will be triggered if there is a pending push
    suppress_hooks_stop(true, false, target_pubkey_hex);

    log(LogLevel::debug, "merge: Complete");
    return good_hashes;
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

void State::received_send_response(
        std::string pubkey, std::vector<seqno_t> seqnos, ustring payload, ustring response) {
    log(LogLevel::debug, "received_send_response: Called");
    auto response_json = nlohmann::json::parse(response);

    if (!response_json.contains("results"))
        throw std::invalid_argument{"Invalid response: expected to contain 'results' array"};
    if (response_json["results"].size() == 0)
        throw std::invalid_argument{"Invalid response: 'results' array is empty"};

    auto results = response_json["results"];

    // Check if all of the results has the same status code
    int single_status_code = -1;
    std::optional<std::string> error_body;
    for (const auto& result : results.items()) {
        if (!result.value().contains("code"))
            throw std::invalid_argument{
                    "Invalid result: expected to contain 'code'" + result.value().dump()};

        // If the code was different from all former codes then break the loop
        auto code = result.value()["code"].get<int>();

        if (single_status_code != -1 && code != single_status_code) {
            single_status_code = 200;
            error_body = std::nullopt;
            break;
        }

        single_status_code = code;

        if (result.value().contains("body") && result.value()["body"].is_string())
            error_body = result.value()["body"].get<std::string>();
    }

    // Throw if all results failed with the same error
    if (single_status_code < 200 || single_status_code > 299) {
        auto error = "Failed with status code: " + std::to_string(single_status_code) + ".";

        // Custom handle a clock out of sync error (v4 returns '425' but included the '406' just in
        // case)
        if (single_status_code == 406 || single_status_code == 425)
            error = "The user's clock is out of sync with the service node network.";
        else if (single_status_code == 401)
            error = "Unauthorised (sinature verification failed).";

        if (error_body)
            error += " Server error: " + *error_body + ".";

        throw std::runtime_error{error};
    }
    log(LogLevel::debug, "received_send_response: Doesn't have a consistent error across requests");

    // If the response includes a timestamp value then we should update the network offset
    if (auto first_result = results[0];
        first_result.contains("body") && first_result["body"].contains("t"))
        network_offset =
                (std::chrono::milliseconds(first_result["body"]["t"].get<long>()) -
                 std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch()));

    // The 'results' array will be in the same order as the requests sent within 'payload' so
    // iterate through them both and mark any successful request as pushed
    auto payload_json = nlohmann::json::parse(payload);

    if (!payload_json.contains("params") || !payload_json["params"].contains("requests"))
        throw std::invalid_argument{
                "Invalid payload: expected to contain 'params.requests' array."};
    if (payload_json["params"]["requests"].size() == 0)
        throw std::invalid_argument{"Invalid payload: 'params.requests' array is empty."};

    auto requests = payload_json["params"]["requests"];
    auto num_configs = requests.size();

    // Subtract one if we also had a 'delete' request to remove obsolete hashes
    if (requests[requests.size() - 1].contains("method") &&
        requests[requests.size() - 1]["method"].get<std::string>() == "delete")
        num_configs -= 1;

    if (seqnos.size() != num_configs)
        throw std::invalid_argument{
                "Invalid seqnos: Size doesn't match the number of config changes."};

    log(LogLevel::debug, "received_send_response: Confirming pushed");
    for (int i = 0, n = results.size(); i < n; ++i) {
        auto result_code = results[i]["code"].get<int>();

        if (result_code < 200 || result_code > 299)
            continue;
        if (!results[i].contains("body"))
            continue;
        if (!results[i]["body"].contains("hash"))
            continue;
        if (!payload_json["params"]["requests"][i].contains("params"))
            continue;
        if (!payload_json["params"]["requests"][i]["params"].contains("namespace"))
            continue;

        auto hash = results[i]["body"]["hash"].get<std::string>();
        auto namespace_ =
                payload_json["params"]["requests"][i]["params"]["namespace"].get<Namespace>();

        switch (namespace_) {
            case Namespace::Contacts: config_contacts->confirm_pushed(seqnos[i], hash); continue;
            case Namespace::ConvoInfoVolatile:
                config_convo_info_volatile->confirm_pushed(seqnos[i], hash);
                continue;
            case Namespace::UserGroups:
                config_user_groups->confirm_pushed(seqnos[i], hash);
                continue;
            case Namespace::UserProfile:
                config_user_profile->confirm_pushed(seqnos[i], hash);
                continue;
            default: break;
        }

        // Other namespaces are unique for a given pubkey
        if (!payload_json["params"]["requests"][i]["params"].contains("pubkey"))
            throw std::invalid_argument{
                    "Invalid payload: Group config change was missing 'pubkey' param."};

        auto pubkey = payload_json["params"]["requests"][i]["params"]["pubkey"].get<std::string>();
        if (pubkey.size() != 66)
            throw std::invalid_argument{"Invalid pubkey: expected 66 characters"};
        if (!_config_groups.count(pubkey))
            throw std::runtime_error{"received_send_response: Unable to retrieve group"};

        // Retrieve the group configs for this pubkey
        auto group_configs = _config_groups[pubkey].get();

        switch (namespace_) {
            case Namespace::GroupInfo: group_configs->config_info->confirm_pushed(seqnos[i], hash);
            case Namespace::GroupMembers:
                group_configs->config_members->confirm_pushed(seqnos[i], hash);
            case Namespace::GroupKeys: continue;  // No need to do anything here
            default: throw std::runtime_error{"Attempted to load unknown namespace"};
        }
    }
    log(LogLevel::debug, "received_send_response: Completed");
}
}  // namespace session::state