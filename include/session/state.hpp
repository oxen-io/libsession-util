#pragma once

#include <session/util.hpp>

#include "config/contacts.hpp"
#include "config/convo_info_volatile.hpp"
#include "config/groups/info.hpp"
#include "config/groups/keys.hpp"
#include "config/groups/members.hpp"
#include "config/namespaces.hpp"
#include "config/user_groups.hpp"
#include "config/user_profile.hpp"
#include "ed25519.hpp"

namespace session::state {

// Levels for the logging callback
enum class LogLevel { debug = 0, info, warning, error };

using Ed25519PubKey = std::array<unsigned char, 32>;
using Ed25519Secret = sodium_array<unsigned char>;

/// Struct containing group configs.
class GroupConfigs {
  public:
    GroupConfigs(ustring_view pubkey, ustring_view user_sk);

    GroupConfigs(GroupConfigs&&) = delete;
    GroupConfigs(const GroupConfigs&) = delete;
    GroupConfigs& operator=(GroupConfigs&&) = delete;
    GroupConfigs& operator=(const GroupConfigs&) = delete;

    std::unique_ptr<session::config::groups::Info> _config_info;
    std::unique_ptr<session::config::groups::Members> _config_members;
    std::unique_ptr<session::config::groups::Keys> _config_keys;
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

    // Invokes the `logger` callback if set, does nothing if there is no logger.
    void log(LogLevel lvl, std::string msg) {
        if (logger)
            logger(lvl, std::move(msg));
    }

  public:
    // Constructs a state with a secretkey that will be used for signing.
    State(ustring_view ed25519_secretkey);

    // Constructs a new state, this will generate a random secretkey and should only be used for
    // creating a new account.
    State() : State(to_unsigned_sv(session::ed25519::ed25519_key_pair().second)){};

    // Object is non-movable and non-copyable; you need to hold it in a smart pointer if it needs to
    // be managed.
    State(State&&) = delete;
    State(const State&) = delete;
    State& operator=(State&&) = delete;
    State& operator=(const State&) = delete;

    // If set then we log things by calling this callback
    std::function<void(LogLevel lvl, std::string msg)> logger;

    /// API: state/State::load
    ///
    /// Loads a dump into the state. Calling this will replace the current config instance with
    /// with a new instance initialised with the provided dump. The USER_GROUPS config must be
    /// loaded before any GROUPS config dumps are loaded or an exception will be thrown.
    ///
    /// Inputs:
    /// - `namespace` -- the namespace where config messages for this dump are stored.
    /// - `pubkey_hex` -- optional pubkey the dump is associated to (in hex). Required for group
    /// dumps.
    /// - `dump` --  binary state data that was previously dumped by calling `dump()`.
    ///
    /// Outputs: None
    void load(
            config::Namespace namespace_,
            std::optional<std::string_view> pubkey_hex,
            ustring_view dump);

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
    /// - `pubkey_hex` -- optional pubkey the dump is associated to (in hex). Required for group
    /// dumps.
    ///
    /// Outputs:
    /// - `ustring` -- Returns binary data of the state dump
    ustring dump(
            config::Namespace namespace_,
            std::optional<std::string_view> pubkey_hex = std::nullopt);

    // User Profile functions
  public:
    /// API: state/State::get_profile_name
    ///
    /// Returns the user profile name, or std::nullopt if there is no profile name set.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::optional<std::string>` - Returns the user profile name if it exists
    std::optional<std::string_view> get_profile_name() const {
        return _config_user_profile->get_name();
    };

    /// API: state/State::set_profile_name
    ///
    /// Sets the user profile name; if given an empty string then the name is removed.
    ///
    /// Inputs:
    /// - `new_name` -- The name to be put into the user profile
    void set_profile_name(std::string_view new_name) { _config_user_profile->set_name(new_name); };

    /// API: user_profile/UserProfile::get_profile_pic
    ///
    /// Gets the user's current profile pic URL and decryption key.  The returned object will
    /// evaluate as false if the URL and/or key are not set.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `profile_pic` - Returns the profile pic
    config::profile_pic get_profile_pic() const { return _config_user_profile->get_profile_pic(); };

    /// API: state/State::set_profile_pic
    ///
    /// Sets the user's current profile pic to a new URL and decryption key.  Clears both if either
    /// one is empty.
    ///
    /// Declaration:
    /// ```cpp
    /// void set_profile_pic(std::string_view url, ustring_view key);
    /// void set_profile_pic(profile_pic pic);
    /// ```
    ///
    /// Inputs:
    /// - First function:
    ///    - `url` -- URL pointing to the profile pic
    ///    - `key` -- Decryption key
    /// - Second function:
    ///    - `pic` -- Profile pic object
    void set_profile_pic(std::string_view url, ustring_view key) {
        _config_user_profile->set_profile_pic(url, key);
    };
    void set_profile_pic(config::profile_pic pic) { _config_user_profile->set_profile_pic(pic); };

    /// API: state/State::get_profile_blinded_msgreqs
    ///
    /// Accesses whether or not blinded message requests are enabled for the client.  Can have three
    /// values:
    ///
    /// - std::nullopt -- the value has not been given an explicit value so the client should use
    ///   its default.
    /// - true -- the value is explicitly enabled (i.e. user wants blinded message requests)
    /// - false -- the value is explicitly disabled (i.e. user disabled blinded message requests)
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::optional<bool>` - true/false if blinded message requests are enabled or disabled;
    ///   `std::nullopt` if the option has not been set either way.
    std::optional<bool> get_profile_blinded_msgreqs() const {
        return _config_user_profile->get_blinded_msgreqs();
    };

    /// API: state/State::set_profile_blinded_msgreqs
    ///
    /// Sets whether blinded message requests (i.e. from SOGS servers you are connected to) should
    /// be enabled or not.  This is typically invoked with either `true` or `false`, but can also be
    /// called with `std::nullopt` to explicitly clear the value.
    ///
    /// Inputs:
    /// - `enabled` -- true if blinded message requests should be retrieved, false if they should
    ///   not, and `std::nullopt` to drop the setting from the config (and thus use the client's
    ///   default).
    void set_profile_blinded_msgreqs(std::optional<bool> enabled) {
        _config_user_profile->set_blinded_msgreqs(enabled);
    };
};

}  // namespace session::state

