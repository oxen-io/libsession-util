#pragma once

#include <chrono>
#include <memory>
#include <session/config.hpp>

#include "base.hpp"
#include "namespaces.hpp"
#include "profile_pic.hpp"

namespace session::config {

using namespace std::literals;

/// keys used in this config, either currently or in the past (so that we don't reuse):
///
/// n - user profile name
/// p - user profile url
/// q - user profile decryption key (binary)
/// + - the priority value for the "Note to Self" pseudo-conversation (higher = higher in the
///     conversation list).  Omitted when 0.  -1 means hidden.
/// e - the expiry timer (in seconds) for the "Note to Self" pseudo-conversation.  Omitted when 0.

class UserProfile final : public ConfigBase {

  public:
    // No default constructor
    UserProfile() = delete;

    /// API: user_profile/UserProfile::UserProfile
    ///
    /// Constructs a user profile from existing data (stored from `dump()`) and the user's secret
    /// key for generating the data encryption key.  To construct a blank profile (i.e. with no
    /// pre-existing dumped data to load) pass `std::nullopt` as the second argument.
    ///
    /// Declaration:
    /// ```cpp
    /// UserProfile(ustring_view ed25519_secretkey, std::optional<ustring_view> dumped);
    /// ```
    ///
    /// Inputs:
    /// - `ed25519_secretkey` -- contains the libsodium secret key used to encrypt/decrypt the
    /// data when pushing/pulling from the swarm.  This can either be the full 64-byte value (which
    /// is technically the 32-byte seed followed by the 32-byte pubkey), or just the 32-byte seed of
    /// the secret key.
    /// - `dumped` -- either `std::nullopt` to construct a new, empty object; or binary state data
    /// that was previously dumped from an instance of this class by calling `dump()`.
    ///
    /// Outputs: 
    /// - `UserProfile` - Constructor
    UserProfile(ustring_view ed25519_secretkey, std::optional<ustring_view> dumped);

    /// API: user_profile/UserProfile::storage_namespace
    ///
    /// Returns the UserProfile namespace. Is constant, will always return 2
    ///
    /// Declaration:
    /// ```cpp
    /// Namespace storage_namespace() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs: 
    /// - `Namespace` - Will return 2
    Namespace storage_namespace() const override { return Namespace::UserProfile; }

    /// API: user_profile/UserProfile::encryption_domain
    ///
    /// Returns the domain. Is constant, will always return "UserProfile"
    ///
    /// Declaration:
    /// ```cpp
    /// const char* encryption_domain() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs: 
    /// - `const char*` - Will return "UserProfile"
    const char* encryption_domain() const override { return "UserProfile"; }

    /// API: user_profile/UserProfile::get_name
    ///
    /// Returns the user profile name, or std::nullopt if there is no profile name set.
    ///
    /// Declaration:
    /// ```cpp
    /// std::optional<std::string_view> get_name() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs: 
    /// - `std::optional<std::string>` - Returns the user profile name if it exists
    std::optional<std::string_view> get_name() const;

    /// API: user_profile/UserProfile::set_name
    ///
    /// Sets the user profile name; if given an empty string then the name is removed.
    ///
    /// Declaration:
    /// ```cpp
    /// void set_name(std::string_view new_name);
    /// ```
    ///
    /// Inputs:
    /// - `new_name` -- The name to be put into the user profile
    ///
    /// Outputs: 
    /// - `void` - Returns nothing
    void set_name(std::string_view new_name);

    /// API: user_profile/UserProfile::get_profile_pic
    ///
    /// Gets the user's current profile pic URL and decryption key.  The returned object will
    /// evaluate as false if the URL and/or key are not set.
    ///
    /// Declaration:
    /// ```cpp
    /// profile_pic get_profile_pic() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs: 
    /// - `profile_pic` - Returns the profile pic
    profile_pic get_profile_pic() const;

    /// API: user_profile/UserProfile::set_profile_pic
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
    ///
    /// Outputs: 
    /// - `void` - Returns nothing
    void set_profile_pic(std::string_view url, ustring_view key);
    void set_profile_pic(profile_pic pic);

    /// API: user_profile/UserProfile::get_nts_priority
    ///
    /// Gets the Note-to-self conversation priority.  Negative means hidden; 0 means unpinned;
    /// higher means higher priority (i.e. hidden in the convo list).
    ///
    /// Declaration:
    /// ```cpp
    /// int get_nts_priority() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs: 
    /// - `int` - Returns a numeric representing prioritity
    int get_nts_priority() const;

    /// API: user_profile/UserProfile::set_nts_priority
    ///
    /// Sets the Note-to-self conversation priority. -1 for hidden, 0 for unpinned, higher for
    /// pinned higher.
    ///
    /// Declaration:
    /// ```cpp
    /// void set_nts_priority(int priority);
    /// ```
    ///
    /// Inputs:
    /// - `priority` -- Numeric representing priority
    ///
    /// Outputs: 
    /// - `void` - Returns nothing
    void set_nts_priority(int priority);

    /// API: user_profile/UserProfile::get_nts_priority
    ///
    /// Returns the current Note-to-self message expiry timer, if set, or std::nullopt if there is
    /// no current expiry timer set.
    ///
    /// Declaration:
    /// ```cpp
    /// std::optional<std::chrono::seconds> get_nts_expiry() const;
    /// ```
    ///
    /// Inputs: None
    ///
    /// Outputs: 
    /// - `std::optional<std::chrono::seconds>` - Returns the timestamp representing the message expiry timer if the timer is set
    std::optional<std::chrono::seconds> get_nts_expiry() const;

    /// API: user_profile/UserProfile::set_nts_priority
    ///
    /// Sets the Note-to-self message expiry timer.  Call without arguments (or pass a zero time) to
    /// disable the expiry timer.
    ///
    /// Declaration:
    /// ```cpp
    /// void set_nts_expiry(std::chrono::seconds timer = 0s);
    /// ```
    ///
    /// Inputs:
    /// - `timer` -- Default to 0 seconds, will set the expiry timer
    ///
    /// Outputs: 
    /// - `void` - Returns nothing
    void set_nts_expiry(std::chrono::seconds timer = 0s);
};

}  // namespace session::config
