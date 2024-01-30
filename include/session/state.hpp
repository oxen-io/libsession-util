#pragma once

#include "config/contacts.hpp"
#include "config/convo_info_volatile.hpp"
#include "config/groups/info.hpp"
#include "config/groups/keys.hpp"
#include "config/groups/members.hpp"
#include "config/namespaces.hpp"
#include "config/user_groups.hpp"
#include "config/user_profile.hpp"
#include "ed25519.hpp"
#include "session/util.hpp"

namespace session::state {

using Ed25519PubKey = std::array<unsigned char, 32>;
using Ed25519Secret = std::array<unsigned char, 64>;

/// Struct containing group configs.
class GroupConfigs {
  public:
    GroupConfigs(ustring_view pubkey, ustring_view user_sk);

    GroupConfigs(GroupConfigs&&) = delete;
    GroupConfigs(const GroupConfigs&) = delete;
    GroupConfigs& operator=(GroupConfigs&&) = delete;
    GroupConfigs& operator=(const GroupConfigs&) = delete;

    std::unique_ptr<session::config::groups::Info> config_info;
    std::unique_ptr<session::config::groups::Members> config_members;
    std::unique_ptr<session::config::groups::Keys> config_keys;
};

struct namespaced_dump {
    config::Namespace namespace_;
    std::optional<std::string_view> pubkey_hex;
    ustring data;

    namespaced_dump(
            config::Namespace namespace_,
            std::optional<std::string_view> pubkey_hex,
            ustring data) :
            namespace_{namespace_}, pubkey_hex{pubkey_hex}, data{data} {};

    namespaced_dump() = delete;
    namespaced_dump(namespaced_dump&&) = default;
    namespaced_dump(const namespaced_dump&) = default;
    namespaced_dump& operator=(namespaced_dump&&) = default;
    namespaced_dump& operator=(const namespaced_dump&) = default;
};

struct config_message {
    config::Namespace namespace_;
    std::string hash;
    uint64_t timestamp_ms;
    ustring data;

    config_message(
            config::Namespace namespace_, std::string hash, uint64_t timestamp_ms, ustring data) :
            namespace_{namespace_}, hash{hash}, timestamp_ms{timestamp_ms}, data{data} {};
    config_message(
            config::Namespace namespace_,
            std::string hash,
            uint64_t timestamp_ms,
            ustring_view data) :
            namespace_{namespace_}, hash{hash}, timestamp_ms{timestamp_ms}, data{data} {};

    config_message() = delete;
    config_message(config_message&&) = default;
    config_message(const config_message&) = default;
    config_message& operator=(config_message&&) = default;
    config_message& operator=(const config_message&) = default;

    auto cmpval() const { return std::tie(namespace_, hash, timestamp_ms, data); }
    bool operator<(const config_message& b) const { return cmpval() < b.cmpval(); }
    bool operator>(const config_message& b) const { return cmpval() > b.cmpval(); }
    bool operator<=(const config_message& b) const { return cmpval() <= b.cmpval(); }
    bool operator>=(const config_message& b) const { return cmpval() >= b.cmpval(); }
    bool operator==(const config_message& b) const { return cmpval() == b.cmpval(); }
    bool operator!=(const config_message& b) const { return cmpval() != b.cmpval(); }
};

class State {
  private:
    // Storage of pubkeys which are currently being suppressed, the value specifies whether the
    // `send` or `store` hook is suppressed.
    std::map<std::string_view, std::pair<bool, bool>> _open_suppressions = {};
    std::map<std::string_view, std::unique_ptr<GroupConfigs>> _config_groups;

  protected:
    Ed25519PubKey _user_pk;
    Ed25519Secret _user_sk;

    std::function<void(
            config::Namespace namespace_,
            std::string prefixed_pubkey,
            uint64_t timestamp_ms,
            ustring data)>
            _store;
    std::function<void(std::string pubkey, std::vector<seqno_t> seqnos, ustring data)> _send;

    // Invokes the `logger` callback if set, does nothing if there is no logger.
    void log(session::config::LogLevel lvl, std::string msg) {
        if (logger)
            logger(lvl, std::move(msg));
    }

  public:
    std::unique_ptr<session::config::Contacts> config_contacts;
    std::unique_ptr<session::config::ConvoInfoVolatile> config_convo_info_volatile;
    std::unique_ptr<session::config::UserGroups> config_user_groups;
    std::unique_ptr<session::config::UserProfile> config_user_profile;

    std::chrono::milliseconds network_offset;

    GroupConfigs* group_config(std::string_view pubkey_hex);

    // Constructs a state with a secretkey that will be used for signing.
    State(ustring_view ed25519_secretkey, std::vector<namespaced_dump> dumps);

    // Constructs a new state, this will generate a random secretkey and should only be used for
    // creating a new account.
    State() : State(to_unsigned_sv(session::ed25519::ed25519_key_pair().second), {}){};

    // Object is non-movable and non-copyable; you need to hold it in a smart pointer if it needs to
    // be managed.
    State(State&&) = delete;
    State(const State&) = delete;
    State& operator=(State&&) = delete;
    State& operator=(const State&) = delete;

    // If set then we log things by calling this callback
    std::function<void(session::config::LogLevel lvl, std::string msg)> logger;

    // Hook which will be called whenever config dumps need to be saved to persistent storage. The
    // hook will immediately be called upon assignment if the state needs to be stored.
    void onStore(std::function<
                 void(config::Namespace namespace_,
                      std::string prefixed_pubkey,
                      uint64_t timestamp_ms,
                      ustring data)> hook) {
        _store = hook;

        if (!hook)
            return;

        _open_suppressions[""] = {false, true};
        suppress_hooks_stop();  // Trigger config change hooks
        _open_suppressions.erase("");
    };

    /// Hook which will be called whenever config messages need to be sent via the API. The hook
    /// will immediately be called upon assignment if the state needs to be pushed.
    ///
    /// Parameters:
    /// - `pubkey` -- the pubkey (in hex) for the swarm where the data should be sent.
    /// - `seqnos` -- a vector of the seqnos for the each updated config message included in the
    /// payload.
    /// - `data` -- payload which should be sent to the API.
    void onSend(std::function<void(std::string pubkey, std::vector<seqno_t> seqnos, ustring data)>
                        hook) {
        _send = hook;

        if (!hook)
            return;

        _open_suppressions[""] = {true, false};
        suppress_hooks_stop();  // Trigger config change hooks
        _open_suppressions.erase("");
    };

    /// API: state/State::load
    ///
    /// Loads a dump into the state. Calling this will replace the current config instance with
    /// with a new instance initialised with the provided dump. The configs must be loaded according
    /// to the order 'namespace_load_order' in 'namespaces.hpp' or an exception will be thrown.
    ///
    /// Inputs:
    /// - `namespace` -- the namespace where config messages for this dump are stored.
    /// - `pubkey_hex` -- optional pubkey the dump is associated to (in hex, with prefix - 66
    /// bytes).
    ///    Required for group dumps.
    /// - `dump` --  binary state data that was previously dumped by calling `dump()`.
    ///
    /// Outputs: None
    void load(
            config::Namespace namespace_,
            std::optional<std::string_view> pubkey_hex,
            ustring_view dump);

    /// API: state/State::config_changed
    ///
    /// This is called internally whenever a config gets dirtied. This function then validates the
    /// state of all config objects associated to the `pubkey_hex` and triggers the `store` and
    /// `send` hooks if needed. If there is an open suppression then the suppressed hook(s) will not
    /// be called.
    ///
    /// Inputs:
    /// - `pubkey_hex` -- optional pubkey the dump is associated to (in hex, with prefix - 66
    /// bytes). Required for group changes.
    ///
    /// Outputs: None
    void config_changed(std::optional<std::string_view> pubkey_hex = std::nullopt);

    /// API: state/State::suppress_hooks_start
    ///
    /// This will suppress the `send` and `store` hooks until `suppress_hooks_stop` is called and
    /// should be used when making multiple config changes to avoid sending and storing unnecessary
    /// partial changes.
    ///
    /// Inputs:
    /// - `send` -- controls whether the `send` hook should be suppressed.
    /// - `store` -- controls whether the `store` hook should be suppressed.
    /// - `pubkey_hex` -- pubkey to suppress changes for (in hex, with prefix - 66
    /// bytes). If none is provided then all changes for all configs will be supressed.
    ///
    /// Outputs: None
    void suppress_hooks_start(
            bool send = true, bool store = true, std::string_view pubkey_hex = "");

    /// API: state/State::suppress_hooks_stop
    ///
    /// This will stop suppressing the `send` and `store` hooks. When this is called, if there are
    /// any pending changes, the `send` and `store` hooks will immediately be called.
    ///
    /// Inputs:
    /// - `send` -- controls whether the `send` hook should no longer be suppressed.
    /// - `store` -- controls whether the `store` hook should no longer be suppressed.
    /// - `pubkey_hex` -- pubkey to stop suppressing changes for (in hex, with prefix - 66 bytes).
    /// If the value provided doesn't match a entry created by `suppress_hooks_start` those
    /// changes will continue to be suppressed. If none is provided then the hooks for all configs
    /// with pending changes will be triggered.
    ///
    /// Outputs: None
    void suppress_hooks_stop(bool send = true, bool store = true, std::string_view pubkey_hex = "");

    /// API: state/State::merge
    ///
    /// This takes all of the messages pulled down from the server and does whatever is necessary to
    /// merge (or replace) the current values.
    ///
    /// Values are pairs of the message hash (as provided by the server) and the raw message body.
    ///
    /// During this call the `send` and `store` callbacks will be triggered at the appropriate times
    /// to correctly update the dump data and push any data to the server again if needed (for
    /// example, because the data contained conflicts that required another update to resolve).
    ///
    /// Returns a vector of successfully merged hashes.
    ///
    /// Will throw on serious error (i.e. if neither the current nor any of the given configs are
    /// parseable).  This should not happen (the current config, at least, should always be
    /// re-parseable).
    ///
    ///
    /// Inputs:
    /// - `pubkey_hex` -- optional pubkey the dump is associated to (in hex, with prefix - 66
    /// bytes).
    ///    Required for group dumps.
    /// - `configs` -- vector of `config_message` types which include the data needed to properly
    /// merge.
    ///
    /// Outputs:
    /// - vector of successfully parsed hashes.  Note that this does not mean the hash was recent or
    ///   that it changed the config, merely that the returned hash was properly parsed and
    ///   processed as a config message, even if it was too old to be useful (or was already known
    ///   to be included).  The hashes will be in the same order as in the input vector.
    std::vector<std::string> merge(
            std::optional<std::string_view> pubkey_hex, const std::vector<config_message>& configs);

    /// API: state/State::dump
    ///
    /// Returns a bt-encoded dict containing the dumps of each of the current config states for
    /// storage in the database; the values in the dict would individually get passed into `load` to
    /// reconstitute the object (including the push/not pushed status).  Resets the `needs_dump()`
    /// flag to false.
    ///
    /// Inputs:
    /// - `full_dump` -- when true the returned bt-encoded dict will include dumps for the entire
    /// state, even if they would normally return `false` for `needs_dump()`.
    ///
    /// Outputs:
    /// - `ustring` -- Returns bt-encoded dict of the state dump
    ustring dump(bool full_dump = false);

    /// API: state/State::dump
    ///
    /// Returns a dump of the current config state for the specified namespace and pubkey for
    /// storage in the database; this value would get passed into `load` to reconstitute the object
    /// (including the push/not pushed status).  Resets the `needs_dump()` flag to false for the
    /// specific config.
    ///
    /// Inputs:
    /// - `namespace` -- the namespace where config messages of the desired dump are stored.
    /// - `pubkey_hex` -- optional pubkey the dump is associated to (in hex, with prefix - 66
    /// bytes). Required for group dumps.
    ///
    /// Outputs:
    /// - `ustring` -- Returns binary data of the state dump
    ustring dump(
            config::Namespace namespace_,
            std::optional<std::string_view> pubkey_hex = std::nullopt);

    /// API: state/State::received_send_response
    ///
    /// Takes the network response from sending the data from the `send` hook and confirms the
    /// configs were successfully pushed.
    ///
    /// Inputs:
    /// - `pubkey` -- the pubkey (in hex, with prefix - 66 bytes) for the swarm where the data was
    /// sent.
    /// - `seqnos` -- the seqnos for each config messages included in the payload.
    /// - `payload_data` -- payload which was sent to the swarm.
    /// - `response_data` -- response that was returned from the swarm.
    void received_send_response(
            std::string pubkey,
            std::vector<seqno_t> seqnos,
            ustring payload_data,
            ustring response_data);
};

};  // namespace session::state
