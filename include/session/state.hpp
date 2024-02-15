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
#include "state.h"

namespace session::state {

class State;

using Ed25519PubKey = std::array<unsigned char, 32>;
using Ed25519Secret = std::array<unsigned char, 64>;

/// Struct containing group configs.
class GroupConfigs {
  public:
    GroupConfigs(
            ustring_view pubkey,
            ustring_view user_sk,
            std::optional<ustring_view> ed25519_secretkey = std::nullopt);

    GroupConfigs(GroupConfigs&&) = delete;
    GroupConfigs(const GroupConfigs&) = delete;
    GroupConfigs& operator=(GroupConfigs&&) = delete;
    GroupConfigs& operator=(const GroupConfigs&) = delete;

    std::unique_ptr<session::config::groups::Info> info;
    std::unique_ptr<session::config::groups::Members> members;
    std::unique_ptr<session::config::groups::Keys> keys;
};

class MutableUserConfigs {
  private:
    State* parent_state;

  public:
    MutableUserConfigs(
            State* state,
            session::config::Contacts& contacts,
            session::config::ConvoInfoVolatile& convo_info_volatile,
            session::config::UserGroups& user_groups,
            session::config::UserProfile& user_profile,
            std::optional<std::function<void(std::string_view err)>> set_error) :
            parent_state(state),
            contacts(contacts),
            convo_info_volatile(convo_info_volatile),
            user_groups(user_groups),
            user_profile(user_profile),
            set_error(set_error) {}

    session::config::Contacts& contacts;
    session::config::ConvoInfoVolatile& convo_info_volatile;
    session::config::UserGroups& user_groups;
    session::config::UserProfile& user_profile;
    std::optional<std::function<void(std::string_view err)>> set_error;

    ~MutableUserConfigs();
};

class MutableGroupConfigs {
  private:
    State* parent_state;

  public:
    MutableGroupConfigs(
            State* state,
            session::config::groups::Info& info,
            session::config::groups::Members& members,
            session::config::groups::Keys& keys,
            std::optional<std::function<void(std::string_view err)>> set_error) :
            parent_state(state), info(info), members(members), keys(keys), set_error(set_error) {}

    session::config::groups::Info& info;
    session::config::groups::Members& members;
    session::config::groups::Keys& keys;
    std::optional<std::function<void(std::string_view err)>> set_error;

    ~MutableGroupConfigs();
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

struct PreparedPush {
    ustring payload;
    std::vector<std::pair<config::Namespace, seqno_t>> namespace_seqno;
};

class State {
  private:
    std::unique_ptr<session::config::Contacts> _config_contacts;
    std::unique_ptr<session::config::ConvoInfoVolatile> _config_convo_info_volatile;
    std::unique_ptr<session::config::UserGroups> _config_user_groups;
    std::unique_ptr<session::config::UserProfile> _config_user_profile;
    std::map<std::string_view, std::unique_ptr<GroupConfigs>> _config_groups;

  protected:
    Ed25519PubKey _user_pk;
    Ed25519Secret _user_sk;
    std::string _user_x_pk_hex;

    std::function<void(
            config::Namespace namespace_,
            std::string prefixed_pubkey,
            uint64_t timestamp_ms,
            ustring data)>
            _store;
    std::function<void(
            std::string pubkey,
            ustring payload,
            std::function<void(bool success, int16_t status_code, ustring response)>
                    received_response)>
            _send;

  public:
    std::chrono::milliseconds network_offset;

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

    // Invokes the `logger` callback if set, does nothing if there is no logger.
    void log(session::config::LogLevel lvl, std::string msg) {
        if (logger)
            logger(lvl, std::move(msg));
    }

    // Hook which will be called whenever config dumps need to be saved to persistent storage. The
    // hook will immediately be called upon assignment if the state needs to be stored.
    void on_store(std::function<
                 void(config::Namespace namespace_,
                      std::string prefixed_pubkey,
                      uint64_t timestamp_ms,
                      ustring data)> hook) {
        _store = hook;

        if (!hook)
            return;

        config_changed(std::nullopt, true, false);

        for (auto& [key, val] : _config_groups)
            config_changed(key, true, false);
    };

    /// Hook which will be called whenever config messages need to be sent via the API. The hook
    /// will immediately be called upon assignment if the state needs to be pushed.
    ///
    /// Parameters:
    /// - `pubkey` -- the pubkey (in hex) for the swarm where the data should be sent.
    /// - `payload` -- payload which should be sent to the API.
    /// - `ctx` -- contextual data which should be used when processing the response.
    /// - `received_response` -- callback which should be called with the response from the send
    /// request.
    void on_send(std::function<
                void(std::string pubkey,
                     ustring payload,
                     std::function<void(bool success, int16_t status_code, ustring response)>
                             received_response)> hook) {
        _send = hook;

        if (!hook)
            return;

        config_changed(std::nullopt, false, true);

        for (auto& [key, val] : _config_groups)
            config_changed(key, false, true);
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
    /// - `allow_store` -- boolean value to specify whether this change can trigger the store hook.
    /// - `allow_send` -- boolean value to specify whether this change can trigger the send hook.
    ///
    /// Outputs: None
    void config_changed(
            std::optional<std::string_view> pubkey_hex = std::nullopt,
            bool allow_store = true,
            bool allow_send = true);

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

    /// API: state/State::current_hashes
    ///
    /// The current config hashes; this can be empty if the current hashes are unknown or the
    /// current state is not clean (i.e. a push is needed or pending).
    ///
    /// Inputs:
    /// - `pubkey_hex` -- optional pubkey to retrieve the hashes for (in hex, with prefix - 66
    /// bytes). Required for group hashes.
    ///
    /// Outputs:
    /// - `std::vector<std::string>` -- Returns current config hashes
    std::vector<std::string> current_hashes(
            std::optional<std::string_view> pubkey_hex = std::nullopt);

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

    /// API: state/State::get_keys
    ///
    /// Returns a vector of encryption keys, in priority order (i.e. element 0 is the encryption
    /// key, and the first decryption key).
    ///
    /// This method is mainly for debugging/diagnostics purposes; most config types have one single
    /// key (based on the secret key), and multi-keyed configs such as groups have their own methods
    /// for encryption/decryption that are already aware of the multiple keys.
    ///
    /// Inputs:
    /// - `namespace` -- the namespace where the desired config messages are stored.
    /// - `pubkey_hex` -- optional pubkey the config is associated to (in hex, with prefix - 66
    /// bytes). Required for group configs.
    ///
    /// Outputs:
    /// - `std::vector<ustring_view>` -- Returns vector of encryption keys
    std::vector<ustring_view> get_keys(
            config::Namespace namespace_, std::optional<std::string_view> pubkey_hex_);

    void create_group(
            std::string_view name,
            std::optional<std::string_view> description,
            std::optional<config::profile_pic> pic,
            std::vector<config::groups::member> members,
            std::function<void(bool success, std::string_view group_id, ustring_view group_sk)>
                    callback);

    void approve_group(std::string_view group_id, std::optional<ustring_view> group_sk);

    // Retrieves a read-only version of the user config
    template <typename ConfigType>
    const ConfigType& config() const;

    // Retrieves a read-only version of the group config for the given public key
    template <typename ConfigType>
    const ConfigType& config(std::string_view pubkey_hex) const;

    // Retrieves an editable version of the user config. Once the returned value is deconstructed it
    // will trigger the `send` and `store` hooks.
    MutableUserConfigs mutable_config(
            std::optional<std::function<void(std::string_view err)>> set_error = std::nullopt);

    // Retrieves an editable version of the group config for the given public key. Once the returned
    // value is deconstructed it will trigger the `send` and `store` hooks.
    MutableGroupConfigs mutable_config(
            std::string_view pubkey_hex,
            std::optional<std::function<void(std::string_view err)>> set_error = std::nullopt);

  private:
    template <typename ConfigType>
    void add_child_logger(ConfigType& base);

    PreparedPush prepare_push(
            std::string pubkey_hex,
            std::chrono::milliseconds timestamp,
            std::vector<config::ConfigBase*> configs);
    void handle_config_push_response(
            std::string pubkey,
            std::vector<std::pair<config::Namespace, seqno_t>> namespace_seqnos,
            bool success,
            uint16_t status_code,
            ustring response);
    void validate_group_pubkey(std::string_view pubkey_hex) const;
};

inline State& unbox(state_object* state) {
    assert(state && state->internals);
    return *static_cast<State*>(state->internals);
}
inline const State& unbox(const state_object* state) {
    assert(state && state->internals);
    return *static_cast<const State*>(state->internals);
}
inline MutableUserConfigs& unbox(mutable_state_user_object* state) {
    assert(state && state->internals);
    return *static_cast<MutableUserConfigs*>(state->internals);
}
inline MutableGroupConfigs& unbox(mutable_state_group_object* state) {
    assert(state && state->internals);
    return *static_cast<MutableGroupConfigs*>(state->internals);
}

inline bool set_error(state_object* state, std::string_view e) {
    if (e.size() > 255)
        e.remove_suffix(e.size() - 255);
    std::memcpy(state->_error_buf, e.data(), e.size());
    state->_error_buf[e.size()] = 0;
    state->last_error = state->_error_buf;
    return false;
}

inline bool set_error_value(char* error, std::string_view e) {
    if (!error)
        return false;

    std::string msg = {e.data(), e.size()};
    if (msg.size() > 255)
        msg.resize(255);
    std::memcpy(error, msg.c_str(), msg.size() + 1);
    return false;
}

};  // namespace session::state
