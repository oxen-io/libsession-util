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
#include "session/config/groups/members.hpp"
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

GroupConfigs::GroupConfigs(
        ustring_view pubkey, ustring_view user_sk, std::optional<ustring_view> ed25519_secretkey) {
    info = std::make_unique<groups::Info>(pubkey, ed25519_secretkey, std::nullopt);
    members = std::make_unique<groups::Members>(pubkey, ed25519_secretkey, std::nullopt);
    keys = std::make_unique<groups::Keys>(
            user_sk, pubkey, ed25519_secretkey, std::nullopt, *info, *members);
}

State::State(ustring_view ed25519_secretkey, std::vector<namespaced_dump> dumps) {
    if (sodium_init() == -1)
        throw std::runtime_error{"libsodium initialization failed!"};
    if (ed25519_secretkey.size() != 64)
        throw std::invalid_argument{"Invalid ed25519_secretkey: expected 64 bytes"};

    // Setup the keys
    std::array<unsigned char, 32> user_x_pk;
    std::memcpy(_user_sk.data(), ed25519_secretkey.data(), ed25519_secretkey.size());
    crypto_sign_ed25519_sk_to_pk(_user_pk.data(), _user_sk.data());

    if (0 != crypto_sign_ed25519_pk_to_curve25519(user_x_pk.data(), _user_pk.data()))
        throw std::runtime_error{"Ed25519 pubkey to x25519 pubkey conversion failed"};

    _user_x_pk_hex.reserve(66);
    _user_x_pk_hex += "05";
    oxenc::to_hex(user_x_pk.begin(), user_x_pk.end(), std::back_inserter(_user_x_pk_hex));

    // Load in the dumps
    auto sorted_dumps = dumps;
    std::sort(sorted_dumps.begin(), sorted_dumps.end(), [](const auto& a, const auto& b) {
        return namespace_load_order(a.namespace_) < namespace_load_order(b.namespace_);
    });

    for (auto dump : sorted_dumps) {
        load(dump.namespace_, dump.pubkey_hex, dump.data);
    }

    // Initialise empty config states for any missing required config types
    if (!_config_contacts) {
        _config_contacts = std::make_unique<Contacts>(ed25519_secretkey, std::nullopt);
        add_child_logger(_config_contacts);
    }

    if (!_config_convo_info_volatile) {
        _config_convo_info_volatile =
                std::make_unique<ConvoInfoVolatile>(ed25519_secretkey, std::nullopt);
        add_child_logger(_config_convo_info_volatile);
    }

    if (!_config_user_groups) {
        _config_user_groups = std::make_unique<UserGroups>(ed25519_secretkey, std::nullopt);
        add_child_logger(_config_user_groups);
    }

    if (!_config_user_profile) {
        _config_user_profile = std::make_unique<UserProfile>(ed25519_secretkey, std::nullopt);
        add_child_logger(_config_user_profile);
    }

    // If we have a group in the 'user_groups' that isn't in the 'invited' state but didn't have a
    // dump for it then most likely the group has been approved but we haven't completed the initial
    // poll - in this case we want to create the group configs because we can assume that the client
    // will try to poll and merge the state into the group
    for (auto group_it = _config_user_groups->begin_groups();
         group_it != _config_user_groups->end();
         ++group_it) {
        if (group_it->invited)
            continue;

        std::optional<ustring_view> group_sk;

        if (!group_it->secretkey.empty())
            group_sk = {group_it->secretkey.data(), group_it->secretkey.size()};

        if (auto [it, b] = _config_groups.try_emplace(group_it->id, nullptr); b) {
            auto ed_pk_data = oxenc::from_hex(group_it->id.begin() + 2, group_it->id.end());
            auto ed_pk = to_unsigned_sv(ed_pk_data);
            _config_groups[group_it->id] =
                    std::make_unique<GroupConfigs>(ed_pk, to_unsigned_sv(_user_sk), group_sk);
        }
    }
}

void State::load(
        Namespace namespace_, std::optional<std::string_view> pubkey_hex_, ustring_view dump) {
    switch (namespace_) {
        case Namespace::Contacts:
            _config_contacts =
                    std::make_unique<Contacts>(to_unsigned_sv({_user_sk.data(), 64}), dump);
            add_child_logger(_config_contacts);
            return;

        case Namespace::ConvoInfoVolatile:
            _config_convo_info_volatile = std::make_unique<ConvoInfoVolatile>(
                    to_unsigned_sv({_user_sk.data(), 64}), dump);
            add_child_logger(_config_convo_info_volatile);
            return;

        case Namespace::UserGroups:
            _config_user_groups =
                    std::make_unique<UserGroups>(to_unsigned_sv({_user_sk.data(), 64}), dump);
            add_child_logger(_config_user_groups);
            return;

        case Namespace::UserProfile:
            _config_user_profile =
                    std::make_unique<UserProfile>(to_unsigned_sv({_user_sk.data(), 64}), dump);
            add_child_logger(_config_user_profile);
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
    auto user_group_info = _config_user_groups->get_group(pubkey_hex);

    if (!user_group_info)
        throw std::runtime_error{
                "Unable to retrieve group " + std::string(pubkey_hex) + " from user_groups config"};

    auto pubkey = session_id_pk(pubkey_hex, "03");
    std::string gid = {pubkey_hex.data(), pubkey_hex.size()};
    ustring_view pubkey_sv = to_unsigned_sv(pubkey);
    ustring_view user_ed25519_secretkey = {_user_sk.data(), 64};
    std::optional<ustring_view> opt_dump = dump;
    std::optional<ustring_view> group_ed25519_secretkey;

    if (!user_group_info.value().secretkey.empty())
        group_ed25519_secretkey = {user_group_info.value().secretkey.data(), 64};

    // Create a fresh `GroupConfigs` state
    if (auto [it, b] = _config_groups.try_emplace(gid, nullptr); b) {
        if (namespace_ == Namespace::GroupKeys)
            throw std::runtime_error{
                    "Attempted to load groups_keys config before groups_info or groups_members "
                    "configs"};

        _config_groups[gid] = std::make_unique<GroupConfigs>(pubkey_sv, user_ed25519_secretkey);
    }

    // Reload the specified namespace with the dump
    if (namespace_ == Namespace::GroupInfo) {
        _config_groups[gid]->info =
                std::make_unique<groups::Info>(pubkey_sv, group_ed25519_secretkey, dump);
        add_child_logger(_config_groups[gid]->info);
    } else if (namespace_ == Namespace::GroupMembers) {
        _config_groups[gid]->members =
                std::make_unique<groups::Members>(pubkey_sv, group_ed25519_secretkey, dump);
        add_child_logger(_config_groups[gid]->members);
    } else if (namespace_ == Namespace::GroupKeys) {
        auto info = _config_groups[gid]->info.get();
        auto members = _config_groups[gid]->members.get();
        auto keys = std::make_unique<groups::Keys>(
                user_ed25519_secretkey, pubkey_sv, group_ed25519_secretkey, dump, *info, *members);
        _config_groups[gid]->keys = std::move(keys);
    } else
        throw std::runtime_error{"Attempted to load unknown namespace"};
}

bool State::has_pending_send() const {
    bool needs_push =
            (_config_contacts->needs_push() || _config_convo_info_volatile->needs_push() ||
             _config_user_groups->needs_push() || _config_user_profile->needs_push());

    if (!needs_push) {
        for (const auto& it : _config_groups) {
            needs_push =
                    (it.second->keys->admin() &&
                     (it.second->info->needs_push() || it.second->members->needs_push() ||
                      it.second->keys->pending_config()));

            if (needs_push)
                break;
        }
    }

    return needs_push;
}

void State::config_changed(
        std::optional<std::string_view> pubkey_hex,
        bool allow_store,
        bool allow_send,
        std::optional<uint64_t> server_timestamp_ms,
        std::optional<std::function<void(bool success, int16_t status_code, ustring response)>>
                after_send) {
    auto is_group_pubkey = (pubkey_hex && !pubkey_hex->empty() && pubkey_hex->substr(0, 2) != "05");
    std::string target_pubkey_hex = (is_group_pubkey ? std::string(*pubkey_hex) : _user_x_pk_hex);

    std::string info_title = "User configs";
    bool needs_push = false;
    bool needs_dump = false;
    std::vector<config::ConfigBase*> configs;
    std::chrono::milliseconds timestamp =
            (std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch()) +
             network_offset);

    if (!is_group_pubkey) {
        needs_push =
                (allow_send &&
                 (_config_contacts->needs_push() || _config_convo_info_volatile->needs_push() ||
                  _config_user_groups->needs_push() || _config_user_profile->needs_push()));
        needs_dump =
                (allow_store &&
                 (_config_contacts->needs_dump() || _config_convo_info_volatile->needs_dump() ||
                  _config_user_groups->needs_dump() || _config_user_profile->needs_dump()));
        configs = {
                _config_contacts.get(),
                _config_convo_info_volatile.get(),
                _config_user_groups.get(),
                _config_user_profile.get()};
    } else {
        // Other namespaces are unique for a given pubkey_hex_
        if (target_pubkey_hex.size() != 66)
            throw std::invalid_argument{"config_changed: Invalid pubkey_hex - expected 66 bytes"};

        // Ensure we have the admin key for the group
        auto user_group_info = _config_user_groups->get_group(target_pubkey_hex);

        if (!user_group_info)
            throw std::runtime_error{
                    "config_changed: Unable to retrieve group " + target_pubkey_hex +
                    " from user_groups config"};

        // Only group admins can push group config changes
        auto& group = _config_groups.at(target_pubkey_hex);
        needs_push =
                (allow_send && !user_group_info->secretkey.empty() &&
                 (group->info->needs_push() || group->members->needs_push() ||
                  group->keys->pending_config()));
        needs_dump =
                (allow_store && (group->info->needs_dump() || group->members->needs_dump() ||
                                 group->keys->needs_dump()));
        configs = {group->info.get(), group->members.get()};
        info_title = "Group configs for " + target_pubkey_hex;
    }

    std::string send_info =
            (!allow_send ? "send suppressed" : ("needs send: " + bool_to_string(needs_push)));
    std::string store_info =
            (!allow_store ? "store suppressed" : ("needs store: " + bool_to_string(needs_dump)));
    log(LogLevel::debug,
        "config_changed: " + info_title + " (" + send_info + ", " + store_info + ")");

    // Call the hook to store the dump if needed
    if (_store && needs_dump && allow_store) {
        std::chrono::milliseconds store_timestamp =
                std::chrono::milliseconds(server_timestamp_ms.value_or(timestamp.count()));
        std::vector<std::pair<Namespace, ustring>> sorted_stores;

        for (auto& config : configs) {
            if (config->needs_dump())
                sorted_stores.emplace_back(config->storage_namespace(), config->dump());
        }

        // GroupKeys needs special handling as it's not a `ConfigBase`
        if (is_group_pubkey && _config_groups[target_pubkey_hex]->keys->needs_dump()) {
            auto config = _config_groups[target_pubkey_hex]->keys.get();
            sorted_stores.emplace_back(config->storage_namespace(), config->dump());
        }

        // Sort the namespaces based on the order they should be merged in to minimise the chance
        // that config messages dependant on others are saved before their dependencies
        std::sort(sorted_stores.begin(), sorted_stores.end(), [](const auto& a, const auto& b) {
            return namespace_merge_order(a.first) < namespace_merge_order(b.first);
        });

        for (auto& info : sorted_stores) {
            log(LogLevel::debug,
                "config_changed: call 'store' for " + namespace_name(info.first) + " in " +
                        target_pubkey_hex);
            _store(info.first, target_pubkey_hex, store_timestamp.count(), info.second);
        }
    }

    // Call the hook to perform a push if needed
    if (_send && needs_push && allow_send) {
        auto push = prepare_push(target_pubkey_hex, timestamp, configs);

        log(LogLevel::debug, "config_changed: Call 'send'");
        _send(target_pubkey_hex,
              push.payload,
              [this,
               pubkey = std::move(target_pubkey_hex),
               push,
               after_send = std::move(after_send)](
                      bool success, uint16_t status_code, ustring response) {
                  handle_config_push_response(pubkey, push.info, success, status_code, response);

                  // Now that we have confirmed the push we need to store the configs again
                  config_changed(pubkey, true, false, std::nullopt);

                  // Call the 'after_send' callback if provided
                  if (after_send)
                      (*after_send)(success, status_code, response);
              });
    }
    log(LogLevel::debug, "config_changed: Complete");
}

PreparedPush State::prepare_push(
        std::string pubkey_hex,
        std::chrono::milliseconds timestamp,
        std::vector<config::ConfigBase*> configs,
        std::optional<ustring> group_sk) {
    auto is_group_pubkey = (!pubkey_hex.empty() && pubkey_hex.substr(0, 2) != "05");
    std::vector<nlohmann::json> requests;
    std::vector<std::string> obsolete_hashes;
    std::array<unsigned char, 64> seckey;

    // Prepare for signing
    if (is_group_pubkey) {
        // If we were given an explicit secret key then use that, otherwise retrieve it from the
        // user groups config
        if (group_sk)
            memcpy(seckey.data(), group_sk->data(), 64);
        else {
            auto config = _config_groups[pubkey_hex]->keys.get();
            auto user_group = _config_user_groups->get_group(pubkey_hex);

            if (!config->admin() || !user_group || user_group->secretkey.empty())
                throw std::runtime_error{
                        "prepare_push: Only groups admins can push config changes"};

            memcpy(seckey.data(), user_group->secretkey.data(), 64);
        }
    } else
        memcpy(seckey.data(), _user_sk.data(), 64);

    // Check the configs for changes
    for (auto& config : configs) {
        if (!config->needs_push())
            continue;

        log(LogLevel::debug,
            "prepare_push: generate push for " + namespace_name(config->storage_namespace()) +
                    ", (" + pubkey_hex + ")");
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

        nlohmann::json params{
                {"namespace", static_cast<int>(config->storage_namespace())},
                {"pubkey", pubkey_hex},
                {"ttl", config->default_ttl().count()},
                {"timestamp", timestamp.count()},
                {"data", oxenc::to_base64(msg)},
        };

        // Sign the request
        if (0 !=
            crypto_sign_ed25519_detached(
                    sig.data(), nullptr, verification.data(), verification.size(), seckey.data()))
            throw std::runtime_error{
                    "prepare_push: Failed to sign; perhaps the secret key is invalid?"};

        params["signature"] = oxenc::to_base64(sig.begin(), sig.end());

        // For user config storage we also need to add `pubkey_ed25519`
        if (!is_group_pubkey)
            params["pubkey_ed25519"] = oxenc::to_hex(_user_pk.begin(), _user_pk.end());

        // Add the 'seqno' temporarily to the params (this will be removed from the payload
        // before sending but is needed for handling the push result)
        params["seqno"] = seqno;

        requests.emplace_back(params);
    }

    // GroupKeys needs special handling as it's not a `ConfigBase`
    if (is_group_pubkey) {
        auto config = _config_groups[pubkey_hex]->keys.get();
        auto pending = config->pending_config();

        if (pending) {
            log(LogLevel::debug,
                "prepare_push: generate push for " + namespace_name(config->storage_namespace()) +
                        ", (" + pubkey_hex + ")");
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
                             seckey.data()))
                throw std::runtime_error{
                        "prepare_push: Failed to sign; perhaps the secret key is invalid?"};

            nlohmann::json params{
                    {"namespace", config->storage_namespace()},
                    {"pubkey", pubkey_hex},
                    {"ttl", config->default_ttl().count()},
                    {"timestamp", timestamp.count()},
                    {"data", oxenc::to_base64(*pending)},
                    {"signature", oxenc::to_base64(sig.begin(), sig.end())},
            };

            // The 'GROUP_KEYS' push data doesn't need a 'seqno', but to avoid index
            // out-of-bounds issues we add one anyway (this will be removed from the payload
            // before sending but is needed for handling the push result)
            params["seqno"] = 0;

            requests.emplace_back(params);
        }
    }

    // Sort the namespaces based on the order they should be stored in to minimise the chance
    // that config messages dependant on others are stored before their dependencies
    auto sorted_requests = requests;
    std::sort(sorted_requests.begin(), sorted_requests.end(), [](const auto& a, const auto& b) {
        return namespace_send_order(static_cast<Namespace>(a["namespace"])) <
               namespace_send_order(static_cast<Namespace>(b["namespace"]));
    });

    std::vector<PreparedPush::Info> push_info;
    nlohmann::json sequence_params;

    for (auto& request : sorted_requests) {
        push_info.push_back(
                {true, true, request["namespace"].get<Namespace>(), request["seqno"].get<seqno_t>()});
        request.erase("seqno");  // Erase the 'seqno' as it shouldn't be in the request payload

        nlohmann::json request_json{{"method", "store"}, {"params", request}};
        sequence_params["requests"].push_back(request_json);
    }

    // Also delete obsolete hashes
    if (!obsolete_hashes.empty()) {
        // Ed25519 signature of `("delete" || messages...)`
        std::array<unsigned char, 64> sig;
        ustring verification = to_unsigned("delete");
        log(LogLevel::debug, "prepare_push: has obsolete hashes");

        for (auto& hash : obsolete_hashes)
            verification += to_unsigned_sv(hash);

        if (0 !=
            crypto_sign_ed25519_detached(
                    sig.data(), nullptr, verification.data(), verification.size(), seckey.data()))
            throw std::runtime_error{
                    "prepare_push: Failed to sign; perhaps the secret key is invalid?"};

        nlohmann::json params{
                {"messages", obsolete_hashes},
                {"pubkey", pubkey_hex},
                {"signature", oxenc::to_base64(sig.begin(), sig.end())},
        };

        // For user config storage we also need to add `pubkey_ed25519`
        if (!is_group_pubkey)
            params["pubkey_ed25519"] = oxenc::to_hex(_user_pk.begin(), _user_pk.end());

        nlohmann::json request_json{{"method", "delete"}, {"params", params}};
        sequence_params["requests"].push_back(request_json);

        // Not strictly needed but means the request count will match
        push_info.push_back({false, false, Namespace::UserProfile, 0});
    }

    nlohmann::json payload{{"method", "sequence"}, {"params", sequence_params}};

    return {to_unsigned(payload.dump()), push_info};
}

std::optional<uint64_t> max_merged_timestamp(
        const std::vector<config_message>& messages,
        const std::vector<std::string>& merged_hashes) {
    if (messages.empty() || merged_hashes.empty())
        return std::nullopt;

    // Filter messages based on merged_hashes
    std::vector<config_message> merged_messages;
    std::copy_if(
            messages.begin(),
            messages.end(),
            std::back_inserter(merged_messages),
            [&merged_hashes](const config_message& msg) {
                return std::find(merged_hashes.begin(), merged_hashes.end(), msg.hash) !=
                       merged_hashes.end();
            });
    auto max_timestamp_message = std::max_element(
            merged_messages.begin(),
            merged_messages.end(),
            [](const config_message& msg1, const config_message& msg2) {
                return msg1.timestamp_ms < msg2.timestamp_ms;
            });

    if (max_timestamp_message != messages.end()) {
        return max_timestamp_message->timestamp_ms;
    }

    return std::nullopt;
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
    std::vector<config_message> pending_configs;
    auto is_group_pubkey = (pubkey_hex && !pubkey_hex->empty() && pubkey_hex->substr(0, 2) != "05");
    std::string target_pubkey_hex = (is_group_pubkey ? std::string(*pubkey_hex) : _user_x_pk_hex);

    // Sanity check the size of the pubkey
    if (target_pubkey_hex.size() != 66)
        throw std::invalid_argument{"merge: Invalid pubkey_hex - expected 66 bytes"};

    for (size_t i = 0; i < sorted_configs.size(); ++i) {
        auto& config = sorted_configs[i];

        // If this is different from the last config, or it's a 'GroupKeys' config (GroupKeys
        // only support individual merging) then clear 'pending_configs' so we can prepare for
        // a new batch-merge
        if (config.namespace_ == Namespace::GroupKeys ||
            (i > 0 && config.namespace_ != sorted_configs[i - 1].namespace_))
            pending_configs.clear();

        pending_configs.emplace_back(config);

        // If this is not a GroupKeys config, the last config or the next config is not in the same
        // namespace then go to the next loop so we can batch-merge the configs in a later loop
        if (config.namespace_ != Namespace::GroupKeys && i != (sorted_configs.size() - 1) &&
            config.namespace_ == sorted_configs[i + 1].namespace_)
            continue;

        // Process the previously grouped configs
        log(LogLevel::debug,
            "merge: Merging " + namespace_name(config.namespace_) + " config (" +
                    std::string(target_pubkey_hex) + ")");
        std::vector<std::pair<std::string, ustring_view>> to_merge;
        to_merge.reserve(pending_configs.size());
        std::transform(
                pending_configs.begin(),
                pending_configs.end(),
                std::back_inserter(to_merge),
                [](const config_message& msg) {
                    return std::pair<std::string, ustring_view>{msg.hash, msg.data};
                });

        std::vector<std::string> merged_hashes;
        switch (config.namespace_) {
            case Namespace::Contacts:
                merged_hashes = _config_contacts->merge(to_merge);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());

                // Immediately store changes if a merge was successful
                if (auto timestamp_ms = max_merged_timestamp(pending_configs, merged_hashes))
                    config_changed(target_pubkey_hex, true, false, timestamp_ms);
                continue;

            case Namespace::ConvoInfoVolatile:
                merged_hashes = _config_convo_info_volatile->merge(to_merge);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());

                // Immediately store changes if a merge was successful
                if (auto timestamp_ms = max_merged_timestamp(pending_configs, merged_hashes))
                    config_changed(target_pubkey_hex, true, false, timestamp_ms);
                continue;

            case Namespace::UserGroups:
                merged_hashes = _config_user_groups->merge(to_merge);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());

                // Immediately store changes if a merge was successful
                if (auto timestamp_ms = max_merged_timestamp(pending_configs, merged_hashes))
                    config_changed(target_pubkey_hex, true, false, timestamp_ms);
                continue;

            case Namespace::UserProfile:
                merged_hashes = _config_user_profile->merge(to_merge);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());

                // Immediately store changes if a merge was successful
                if (auto timestamp_ms = max_merged_timestamp(pending_configs, merged_hashes))
                    config_changed(target_pubkey_hex, true, false, timestamp_ms);
                continue;

            default: break;
        }

        // Other namespaces are unique for a given pubkey_hex_
        if (!pubkey_hex)
            throw std::invalid_argument{
                    "merge: Invalid pubkey_hex - required for group config namespaces"};

        auto& group = _config_groups.at(target_pubkey_hex);
        auto info = group->info.get();
        auto members = group->members.get();
        is_group_merge = true;

        switch (config.namespace_) {
            case Namespace::GroupInfo:
                merged_hashes = info->merge(to_merge);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());

                // Immediately store changes if a merge was successful
                if (auto timestamp_ms = max_merged_timestamp(pending_configs, merged_hashes))
                    config_changed(target_pubkey_hex, true, false, timestamp_ms);
                continue;

            case Namespace::GroupMembers:
                merged_hashes = members->merge(to_merge);
                good_hashes.insert(good_hashes.end(), merged_hashes.begin(), merged_hashes.end());

                // Immediately store changes if a merge was successful
                if (auto timestamp_ms = max_merged_timestamp(pending_configs, merged_hashes))
                    config_changed(target_pubkey_hex, true, false, timestamp_ms);
                continue;

            case Namespace::GroupKeys:
                // GroupKeys doesn't support merging multiple messages at once so do them
                // individually
                if (group->keys->load_key_message(
                            config.hash, config.data, config.timestamp_ms, *info, *members)) {
                    good_hashes.emplace_back(config.hash);
                    config_changed(target_pubkey_hex, true, false, config.timestamp_ms);
                }
                continue;

            default: throw std::runtime_error{"merge: Attempted to merge from unknown namespace"};
        }
    }

    // If two admins rekeyed for different member changes at the same time then there is a "key
    // collision" and the "needs rekey" function will return true to indicate that a 3rd `rekey`
    // needs to be made to have a final set of keys which includes all members
    if (is_group_merge) {
        auto& group = _config_groups.at(target_pubkey_hex);

        if (group->keys->needs_rekey()) {
            auto info = group->info.get();
            auto members = group->members.get();
            group->keys->rekey(*info, *members);
        }
    }

    // Now that all of the merges have been completed we want to trigger the `send` hook just in
    // case if there is a pending push (the 'server_timestamp_ms' is only needed for the `store`
    // hook so no need to pass here)
    config_changed(target_pubkey_hex, false, true, std::nullopt);

    log(LogLevel::debug, "merge: Complete");
    return good_hashes;
}

std::vector<std::string> State::current_hashes(std::optional<std::string_view> pubkey_hex) {
    std::vector<std::string> result;

    if (!pubkey_hex || pubkey_hex->empty() || pubkey_hex->substr(0, 2) == "05") {
        auto contact_hashes = _config_contacts->current_hashes();
        auto convo_info_volatile_hashes = _config_convo_info_volatile->current_hashes();
        auto user_group_hashes = _config_user_groups->current_hashes();
        auto user_profile_hashes = _config_user_profile->current_hashes();
        result.insert(result.end(), contact_hashes.begin(), contact_hashes.end());
        result.insert(
                result.end(), convo_info_volatile_hashes.begin(), convo_info_volatile_hashes.end());
        result.insert(result.end(), user_group_hashes.begin(), user_group_hashes.end());
        result.insert(result.end(), user_profile_hashes.begin(), user_profile_hashes.end());
    } else {
        if (pubkey_hex->size() != 66)
            throw std::invalid_argument{"current_hashes: Invalid pubkey_hex - expected 66 bytes"};

        std::string gid = {pubkey_hex->data(), pubkey_hex->size()};
        auto& group = _config_groups.at(gid);
        auto info_hashes = group->info->current_hashes();
        auto members_hashes = group->members->current_hashes();
        auto keys_hashes = group->keys->current_hashes();
        result.insert(result.end(), info_hashes.begin(), info_hashes.end());
        result.insert(result.end(), members_hashes.begin(), members_hashes.end());
        result.insert(result.end(), keys_hashes.begin(), keys_hashes.end());
    }

    return result;
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
            if (full_dump || config->info->needs_dump() || config->keys->needs_dump() ||
                config->members->needs_dump()) {
                oxenc::bt_dict_producer group_combined = combined.append_dict(key);

                if (full_dump || config->info->needs_dump())
                    group_combined.append("info", session::from_unsigned_sv(config->info->dump()));

                if (full_dump || config->keys->needs_dump())
                    group_combined.append("keys", session::from_unsigned_sv(config->keys->dump()));

                if (full_dump || config->members->needs_dump())
                    group_combined.append(
                            "members", session::from_unsigned_sv(config->members->dump()));
            }
        }
    }

    auto to_dump = std::move(combined).str();

    return session::ustring{to_unsigned_sv(to_dump)};
}

ustring State::dump(config::Namespace namespace_, std::optional<std::string_view> pubkey_hex) {
    switch (namespace_) {
        case Namespace::Contacts: return _config_contacts->dump();
        case Namespace::ConvoInfoVolatile: return _config_convo_info_volatile->dump();
        case Namespace::UserGroups: return _config_user_groups->dump();
        case Namespace::UserProfile: return _config_user_profile->dump();
        default: break;
    }

    // Other namespaces are unique for a given pubkey_hex
    if (!pubkey_hex)
        throw std::invalid_argument{
                "Invalid pubkey_hex: pubkey_hex required for group config namespaces"};
    if (pubkey_hex->size() != 64)
        throw std::invalid_argument{"Invalid pubkey_hex: expected 64 bytes"};

    // Retrieve the group configs for this pubkey
    std::string gid = {pubkey_hex->data(), pubkey_hex->size()};
    auto& group = _config_groups.at(gid);

    switch (namespace_) {
        case Namespace::GroupInfo: return group->info->dump();
        case Namespace::GroupMembers: return group->members->dump();
        case Namespace::GroupKeys: return group->keys->dump();
        default: throw std::runtime_error{"Attempted to load unknown namespace"};
    }
}

std::optional<std::string> extract_error(int status_code, ustring response) {
    if (response.empty())
        return std::nullopt;

    std::string response_string = {from_unsigned(response.data()), response.size()};

    try {
        auto response_json = nlohmann::json::parse(response);

        // If the status code for the root request failed then try to extract the 'reason',
        // otherwise just return the response as the error
        if (status_code < 200 || status_code > 299) {
            if (response_json.contains("reason"))
                return response_json["reason"].get<std::string>();
            else
                return response_string;
        }

        // If it wasn't a batch/sequence request then assume it was successful and return no error
        if (!response_json.contains("results"))
            return std::nullopt;

        auto results = response_json["results"];

        // Check if all of the results has the same status code
        int single_status_code = -1;
        std::optional<std::string> error_body;
        for (const auto& result : results.items()) {
            // Invalid subresponse, just return the response as the error
            if (!result.value().contains("code"))
                return response_string;

            auto code = result.value()["code"].get<int>();

            // If the code was different from all former codes then there wasn't a single error (ie.
            // it needs specific handling) so return no error
            if (single_status_code != -1 && code != single_status_code)
                return std::nullopt;

            single_status_code = code;

            if (result.value().contains("body") && result.value()["body"].is_string())
                error_body = result.value()["body"].get<std::string>();
        }

        // Return the error if all results failed with the same error
        if (single_status_code < 200 || single_status_code > 299) {
            // Custom handle a clock out of sync error (v4 returns '425' but included the '406' just
            // in case)
            if (single_status_code == 406 || single_status_code == 425)
                return "The user's clock is out of sync with the service node network.";

            return error_body.value_or(
                    "Failed with status code: " + std::to_string(single_status_code) + ".");
        }

        return std::nullopt;
    } catch (...) {
        return response_string;
    }
}

void State::handle_config_push_response(
        std::string pubkey,
        std::vector<PreparedPush::Info> push_info,
        bool success,
        uint16_t status_code,
        ustring response) {
    // If the request failed then just error
    if (auto error = extract_error(status_code, response); error)
        throw std::runtime_error{*error};

    log(LogLevel::debug, "handle_config_push_response: No simple error detected.");

    // Otherwise process the response data
    auto response_json = nlohmann::json::parse(response);

    if (!response_json.contains("results"))
        throw std::invalid_argument{
                "handle_config_push_response: Invalid response - expected to contain 'results' "
                "array"};
    if (response_json["results"].size() == 0)
        throw std::invalid_argument{
                "handle_config_push_response: Invalid response - 'results' array is empty"};

    // If the response includes a timestamp value then we should update the network offset
    auto results = response_json["results"];

    if (auto first_result = results[0];
        first_result.contains("body") && first_result["body"].contains("t"))
        network_offset =
                (std::chrono::milliseconds(first_result["body"]["t"].get<long>()) -
                 std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch()));

    size_t required_response_count =
            std::count_if(push_info.begin(), push_info.end(), [](const PreparedPush::Info& info) {
                return info.requires_response;
            });
    if (results.size() < required_response_count)
        throw std::invalid_argument{
                "handle_config_push_response: Invalid response - Number of responses smaller than "
                "the number of requests requiring responses."};

    for (int i = 0, n = results.size(); i < n; ++i) {
        if (!push_info[i].is_config_push)
            continue;

        auto result_code = results[i]["code"].get<int>();

        if (result_code < 200 || result_code > 299 || !results[i].contains("body") ||
            !results[i]["body"].contains("hash"))
            continue;

        auto hash = results[i]["body"]["hash"].get<std::string>();

        switch (push_info[i].namespace_) {
            case Namespace::Contacts:
                _config_contacts->confirm_pushed(push_info[i].seqno, hash);
                continue;
            case Namespace::ConvoInfoVolatile:
                _config_convo_info_volatile->confirm_pushed(push_info[i].seqno, hash);
                continue;
            case Namespace::UserGroups:
                _config_user_groups->confirm_pushed(push_info[i].seqno, hash);
                continue;
            case Namespace::UserProfile:
                _config_user_profile->confirm_pushed(push_info[i].seqno, hash);
                continue;
            default: break;
        }

        // Other namespaces are unique for a given pubkey
        auto& group = _config_groups.at(pubkey);

        switch (push_info[i].namespace_) {
            case Namespace::GroupInfo:
                group->info->confirm_pushed(push_info[i].seqno, hash);
                continue;
            case Namespace::GroupMembers:
                group->members->confirm_pushed(push_info[i].seqno, hash);
                continue;
            case Namespace::GroupKeys: continue;  // No need to do anything here
            default:
                throw std::runtime_error{
                        "handle_config_push_response: Attempted to load unknown namespace"};
        }
    }

    log(LogLevel::debug, "handle_config_push_response: Completed");
}

std::vector<ustring_view> State::get_keys(
        Namespace namespace_, std::optional<std::string_view> pubkey_hex) {
    switch (namespace_) {
        case Namespace::Contacts: return _config_contacts->get_keys();
        case Namespace::ConvoInfoVolatile: return _config_convo_info_volatile->get_keys();
        case Namespace::UserGroups: return _config_user_groups->get_keys();
        case Namespace::UserProfile: return _config_user_profile->get_keys();
        default: break;
    }

    // Other namespaces are unique for a given pubkey_hex
    if (!pubkey_hex)
        throw std::invalid_argument{
                "Invalid pubkey_hex: pubkey_hex required for group config namespaces"};
    if (pubkey_hex->size() != 64)
        throw std::invalid_argument{"Invalid pubkey_hex: expected 64 bytes"};

    // Retrieve the group configs for this pubkey
    std::string gid = {pubkey_hex->data(), pubkey_hex->size()};
    auto& group = _config_groups.at(gid);

    switch (namespace_) {
        case Namespace::GroupInfo: return group->info->get_keys();
        case Namespace::GroupMembers: return group->members->get_keys();
        case Namespace::GroupKeys: return group->keys->group_keys();
        default: throw std::runtime_error{"Attempted to load unknown namespace"};
    }
}

void State::create_group(
        std::string_view name,
        std::optional<std::string_view> description,
        std::optional<profile_pic> pic,
        std::vector<groups::member> members_,
        std::function<void(
                std::string_view group_id, ustring_view group_sk, std::optional<std::string> error)>
                callback) {
    auto key_pair = ed25519::ed25519_key_pair();
    auto group_id = "03" + oxenc::to_hex(key_pair.first.begin(), key_pair.first.end());
    ustring ed_pk = {key_pair.first.data(), key_pair.first.size()};
    ustring ed_sk = {key_pair.second.data(), key_pair.second.size()};
    std::chrono::milliseconds timestamp =
            (std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch()) +
             network_offset);

    // Sanity check to avoid group collision
    if (auto [it, b] = _config_groups.try_emplace(group_id, nullptr); b) {
        _config_groups[group_id] = std::make_unique<GroupConfigs>(ed_pk, to_unsigned_sv(_user_sk));
    } else {
        throw std::runtime_error{"create_group: Tried to create group matching an existing group"};
    }

    // Store the group info
    assert(_config_groups[group_id]);
    auto& group = _config_groups.at(group_id);
    group->info = std::make_unique<groups::Info>(ed_pk, ed_sk, std::nullopt);
    group->info->set_name(name);
    group->info->set_created(timestamp.count());

    if (description)
        group->info->set_description(*description);

    if (pic)
        group->info->set_profile_pic(*pic);

    // Need to load the members before creating the Keys config to ensure they
    // are included in the initial key rotation
    group->members = std::make_unique<groups::Members>(ed_pk, ed_sk, std::nullopt);

    // Insert the current user as a group admin
    auto admin_member = groups::member{_user_x_pk_hex};
    admin_member.admin = true;
    admin_member.profile_picture = _config_user_profile->get_profile_pic();

    if (auto name = _config_user_profile->get_name())
        admin_member.name = *name;

    group->members->set(admin_member);

    // Add other members (ignore the current user if they happen to be included)
    for (auto m : members_)
        if (m.session_id != _user_x_pk_hex)
            group->members->set(m);

    // Finally create the keys
    auto info = group->info.get();
    auto members = group->members.get();
    group->keys = std::make_unique<groups::Keys>(
            to_unsigned_sv(_user_sk), ed_pk, ed_sk, std::nullopt, *info, *members);

    // Prepare and trigger the push for the group configs (need to explicitly provide the 'ed_sk'
    // here as we won't load the group into user groups until after we have successfully pushed the
    // group configs)
    std::vector<config::ConfigBase*> configs = {group->info.get(), group->members.get()};
    auto push = prepare_push(group_id, timestamp, configs, ed_sk);

    _send(group_id,
          push.payload,
          [this,
           gid = std::move(group_id),
           push_info = push.info,
           secretkey = std::move(ed_sk),
           n = std::move(name),
           timestamp,
           cb = std::move(callback)](bool success, int16_t status_code, ustring response) {
              try {
                  // Call through to the default 'handle_config_push_response' first to update it's
                  // state correctly (this will also result in the configs getting stored to disk)
                  handle_config_push_response(gid, push_info, success, status_code, response);

                  // Retrieve the group configs for this pubkey and setup an entry in the user
                  // groups config for it (the 'at' call will throw if the group doesn't exist)
                  _config_groups.at(gid);
                  auto user_group = _config_user_groups->get_or_construct_group(gid);
                  user_group.name = n;
                  user_group.joined_at = timestamp.count();
                  user_group.secretkey = secretkey;
                  _config_user_groups->set(user_group);

                  // Manually trigger 'config_changed' because we modified '_config_user_groups'
                  // directly rather than via the 'MutableUserConfigs' so it won't automatically get
                  // triggered
                  config_changed(std::nullopt, true, true, std::nullopt);

                  // Now that we have a `_config_user_groups` entry for the group and have confirmed
                  // the push we need to store the group configs (we can't do this until after the
                  // `_config_user_groups` has been updated)
                  config_changed(gid, true, false, std::nullopt);

                  // Lastly trigger the 'callback' to communicate the group was successfully created
                  cb(gid, secretkey, std::nullopt);
              } catch (const std::exception& e) {
                  cb(""sv, ""_usv, e.what());
              }
          });
}

void State::approve_group(std::string_view group_id) {
    std::string gid = {group_id.data(), group_id.size()};

    // If we don't already have GroupConfigs then create them
    if (auto [it, b] = _config_groups.try_emplace(gid, nullptr); b) {
        auto ed_pk_data = oxenc::from_hex(group_id.begin() + 2, group_id.end());
        auto ed_pk = to_unsigned_sv(ed_pk_data);
        _config_groups[gid] =
                std::make_unique<GroupConfigs>(ed_pk, to_unsigned_sv(_user_sk), std::nullopt);
    }

    // Update the USER_GROUPS config to have the group marked as approved
    auto group = _config_user_groups->get_or_construct_group(group_id);
    group.invited = false;
    _config_user_groups->set(group);

    // Trigger the 'config_changed' callback directly since we aren't using 'MutableUserConfig' (We
    // don't call it for the group config because there is no data so it's likely we are creating
    // the initial state upon accepting an invite so have no data yet)
    config_changed(std::nullopt, true, true, std::nullopt);
}

void State::load_group_admin_key(std::string_view group_id, ustring_view secret) {
    if (secret.size() == 64)
        secret.remove_suffix(32);
    else if (secret.size() != 32)
        throw std::invalid_argument{
                "Failed to load admin key: invalid secret key (expected 32 or 64 bytes)"};

    std::string gid = {group_id.data(), group_id.size()};
    std::array<unsigned char, 32> pk;
    sodium_cleared<std::array<unsigned char, 64>> sk;
    crypto_sign_ed25519_seed_keypair(pk.data(), sk.data(), secret.data());

    // Load the secret key into the Keys config
    auto& group = _config_groups.at(gid);
    auto info = group->info.get();
    auto members = group->members.get();
    group->keys->load_admin_key(secret, *info, *members);

    // Update the group member record to flag the current user as an admin
    auto member = members->get_or_construct(_user_x_pk_hex);
    member.admin = true;
    member.invite_status = 0;  // Just in case
    member.promotion_status = 0;
    group->members->set(member);

    // Update the user groups record to include the admin key
    auto user_group = _config_user_groups->get_or_construct_group(group_id);
    user_group.secretkey = {sk.data(), sk.size()};
    _config_user_groups->set(user_group);

    // Trigger the 'config_changed' callbacks directly since we aren't using 'MutableUserConfig' (We
    // don't call it for the group config because there is no data so it's likely we are creating
    // the initial state upon accepting an invite so have no data yet)
    config_changed(std::nullopt, true, true, std::nullopt);
    config_changed(group_id, true, true, std::nullopt);
}

void State::add_group_members(
        std::string_view group_id,
        bool supplemental_rotation,
        const std::vector<groups::member> members,
        std::function<void(std::optional<std::string_view> error)> callback) {
    if (members.empty()) {
        callback(std::nullopt);
        return;
    }

    std::string gid = {group_id.data(), group_id.size()};
    auto& group = _config_groups.at(gid);
    std::chrono::milliseconds timestamp =
            (std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch()) +
             network_offset);

    // Add the members to Members
    for (auto m : members)
        group->members->set(m);

    // Don't bother rotating the keys if there are only admins
    size_t non_admin_count = std::count_if(members.begin(), members.end(), [](const groups::member& m) {
        return !m.admin;
    });

    // If there are non-admins and it's not a supplemental rotation then do a rekey
    if (non_admin_count > 0 && !supplemental_rotation) {
        auto info = _config_groups[gid]->info.get();
        auto members = _config_groups[gid]->members.get();
        group->keys->rekey(*info, *members);
    }

    // Prepare the push payload for the group configs
    std::vector<config::ConfigBase*> configs = {group->info.get(), group->members.get()};
    auto push = prepare_push(gid, timestamp, configs);

    // If there are non-admins and it's a supplemental rotation then we want to include the key supplement within the batch
    // request we are going to send
    if (non_admin_count > 0 && supplemental_rotation) {
        std::vector<std::string> sids;
        std::transform(
                members.begin(),
                members.end(),
                std::back_inserter(sids),
                [](const groups::member& m) { return m.session_id; });
        auto msg = group->keys->key_supplement(sids);
        auto [pubkey, payload] = group->keys->prepare_supplement_payload(msg, timestamp);

        // We need to update the current payload (we want to insert the supplement to the beginning
        // of the batch requests)
        auto updated_push_info = push.info;
        auto updated_payload = nlohmann::json::parse(push.payload);
        auto payload_json = nlohmann::json::parse(payload);
        auto requests_ptr = nlohmann::json::json_pointer("/params/requests");

        if (!updated_payload.contains(requests_ptr))
            throw std::runtime_error{"add_group_members: Prepared payload structure is invalid."};

        // No seqno for keys messages
        auto updated_requests = updated_payload[requests_ptr];
        updated_requests.insert(updated_requests.begin(), payload_json);
        updated_payload[requests_ptr] = updated_requests;
        updated_push_info.insert(updated_push_info.begin(), {false, true, Namespace::UserProfile, 0});
        push = {to_unsigned(updated_payload.dump()), updated_push_info};
    }

    _send(gid,
          push.payload,
          [this, gid = std::move(gid), push_info = push.info, cb = std::move(callback)](
                  bool success, int16_t status_code, ustring response) {
              try {
                  // Call through to the default 'handle_config_push_response' first to update it's
                  // state correctly (this will also result in the configs getting stored to disk)
                  handle_config_push_response(gid, push_info, success, status_code, response);
                  cb(std::nullopt);
              } catch (const std::exception& e) {
                  cb(e.what());
              }
          });
}

void State::erase_group(std::string_view group_id, bool remove_user_record) {
    std::string gid = {group_id.data(), group_id.size()};

    // Remove the group configs
    _config_groups.erase(gid);

    // If we don't want to remove the user record then stop here
    if (!remove_user_record)
        return;

    _config_user_groups->erase_group(group_id);

    // Trigger the 'config_changed' callback directly since we aren't using 'MutableUserConfig' (We
    // don't call it for the group config because there is no data so it's likely we are creating
    // the initial state upon accepting an invite so have no data yet)
    config_changed(std::nullopt, true, true, std::nullopt);
}

// Template functions

template <typename ConfigType>
void State::add_child_logger(ConfigType& config) {
    config->logger = [this](LogLevel lvl, std::string msg) { log(lvl, msg); };
}

template <typename ConfigType>
const ConfigType& State::config() const {
    throw std::runtime_error{"config: Attempted to retrieve config for unknown namespace"};
};

template <typename ConfigType>
const ConfigType& State::config(std::string_view pubkey_hex) const {
    throw std::runtime_error{"config: Attempted to retrieve config for unknown namespace"};
};

template <>
const Contacts& State::config() const {
    return *_config_contacts;
}

template <>
const ConvoInfoVolatile& State::config() const {
    return *_config_convo_info_volatile;
};

template <>
const UserGroups& State::config() const {
    return *_config_user_groups;
};

template <>
const UserProfile& State::config() const {
    return *_config_user_profile;
};

template <>
const groups::Info& State::config(std::string_view pubkey_hex) const {
    if (pubkey_hex.size() != 66)
        throw std::invalid_argument{"config: Invalid pubkey_hex - expected 66 bytes"};
    return *_config_groups.at({pubkey_hex.data(), pubkey_hex.size()})->info;
};

template <>
const groups::Members& State::config(std::string_view pubkey_hex) const {
    if (pubkey_hex.size() != 66)
        throw std::invalid_argument{"config: Invalid pubkey_hex - expected 66 bytes"};
    return *_config_groups.at({pubkey_hex.data(), pubkey_hex.size()})->members;
};

template <>
const groups::Keys& State::config(std::string_view pubkey_hex) const {
    if (pubkey_hex.size() != 66)
        throw std::invalid_argument{"config: Invalid pubkey_hex - expected 66 bytes"};
    return *_config_groups.at({pubkey_hex.data(), pubkey_hex.size()})->keys;
};

MutableUserConfigs State::mutable_config(
        std::optional<std::function<void(std::string_view err)>> set_error) {
    return MutableUserConfigs(
            this,
            *_config_contacts,
            *_config_convo_info_volatile,
            *_config_user_groups,
            *_config_user_profile,
            set_error);
};

MutableUserConfigs::~MutableUserConfigs() {
    parent_state->config_changed(std::nullopt, true, true, std::nullopt);
};

MutableGroupConfigs State::mutable_config(
        std::string_view pubkey_hex,
        std::optional<std::function<void(std::string_view err)>> set_error) {
    if (pubkey_hex.size() != 66)
        throw std::invalid_argument{"config: Invalid pubkey_hex - expected 66 bytes"};

    std::string gid = {pubkey_hex.data(), pubkey_hex.size()};
    return MutableGroupConfigs(
            *this,
            *_config_groups[gid]->info,
            *_config_groups[gid]->members,
            *_config_groups[gid]->keys,
            set_error);
};

std::chrono::milliseconds MutableGroupConfigs::get_network_offset() const {
    return parent_state.network_offset;
};

MutableGroupConfigs::~MutableGroupConfigs() {
    parent_state.config_changed(info.id, true, true, std::nullopt);
};

}  // namespace session::state
