#pragma once

#include <chrono>
#include <memory>
#include <session/config.hpp>

#include "../base.hpp"
#include "../namespaces.hpp"
#include "../profile_pic.hpp"

struct config_group_member;

namespace session::config::groups {

using namespace std::literals;

/// keys used in this config, either currently or in the past (so that we don't reuse):
///
/// m - dict of members; each key is the member session id (33 bytes), each value is a dict
/// containing subkeys:
///   n - member name; this will always be set in the encoded message to prevent dict pruning, but
///       will be an empty string if there is no name.
///   p - member profile pic url
///   q - member profile pic decryption key (binary)
///   I - invite status; this will be one of:
///       - 1 if the invite has been issued but not yet accepted.
///       - 2 if an invite was created but failed to send for some reason (and thus can be resent)
///       - omitted once an invite is accepted.  (This also gets omitted if the `A` admin flag gets
///         set).
///   s - invite supplemental keys flag (only set when `I` is set): if set (to 1) then this invite
///       was issued with the intention of sending the user the existing active decryption keys
///       (allowing them to access current messages); if omitted (with `I` set) then the invitation
///       was not meant to give access to past configs/messages (and was presumably issued with a
///       group rekey).
///   A - flag set to 1 if the member is an admin, omitted otherwise.
///   P - promotion (to admin) status; this will be one of:
///       - 1 if a promotion has been sent.
///       - 2 if a promotion was created but failed to send for some reason (and thus should be
///         resent)
///       - omitted once the promotion is accepted (i.e. once `A` gets set).

constexpr int INVITE_SENT = 1, INVITE_FAILED = 2;
constexpr int REMOVED_MEMBER = 1, REMOVED_MEMBER_AND_MESSAGES = 2;

/// Struct containing member details
struct member {
    static constexpr size_t MAX_NAME_LENGTH = 100;

    explicit member(std::string sid);

    // Internal ctor/method for C API implementations:
    explicit member(const config_group_member& c);  // From c struct

    /// API: groups/member::session_id
    ///
    /// Member variable
    ///
    /// The member's session ID, in hex.
    std::string session_id;

    /// API: groups/member::name
    ///
    /// Member variable
    ///
    /// The member's human-readable name.  Optional.  This is used by other members of the group to
    /// display a member's details before having seen a message from that member.
    std::string name;

    /// API: groups/member::profile_picture
    ///
    /// Member variable
    ///
    /// The member's profile picture (URL & decryption key).  Optional.  This is used by other
    /// members of the group to display a member's details before having seen a message from that
    /// member.
    profile_pic profile_picture;

    /// API: groups/member::admin
    ///
    /// Member variable
    ///
    /// Flag that is set to indicate to the group that this member is an admin.
    ///
    /// Note that this is only informative but isn't a permission gate: someone could still possess
    /// the admin keys without this (e.g. if they cleared the flag to appear invisible), or could
    /// have lost (or never had) the keys even if this is set.
    ///
    /// See also `promoted()` if you want to check for either an admin or someone being promoted to
    /// admin.
    bool admin = false;

    /// API: groups/member::supplement
    ///
    /// Member variable
    ///
    /// Flag that is set to indicate to the group that this member was added with a supplemental key
    /// rotation so that other admins can trigger the same key rotation method if they send a new
    /// invitation to the same member.
    ///
    /// Note that this should be cleared when a member accepts an invitation.
    bool supplement = false;

    // Flags to track an invited user.  This value is typically not used directly, but rather via
    // the `set_invited()`, `invite_pending()` and similar methods.
    int invite_status = 0;

    /// API: groups/member::set_invited
    ///
    /// Sets the "invited" flag for this user.  This marks the user as having a pending invitation
    /// to the group.  The optional `failed` parameter can be specified as true if the invitation
    /// was issued but failed to send for some reason (this is intended as a signal to other clients
    /// that the invitation should be reissued).
    ///
    /// Inputs:
    /// - `failed` can be specified and set to `true` to set the invite status to "failed-to-send";
    ///   otherwise omitting it or giving as `false` sets the invite status to "sent."
    void set_invited(bool failed = false) { invite_status = failed ? INVITE_FAILED : INVITE_SENT; }

    /// API: groups/members::set_accepted
    ///
    /// This clears the "invited" and "supplement" flags for this user, thus indicating that the
    /// user has accepted an invitation and is now a regular member of the group.
    ///
    /// Inputs: none
    void set_accepted() {
        invite_status = 0;
        supplement = false;
    }

    /// API: groups/member::invite_pending
    ///
    /// Returns whether the user currently has a pending invitation.  Returns true if so (whether or
    /// not that invitation has failed).
    ///
    /// Inputs: none
    ///
    /// Outputs:
    /// - `bool` -- true if the user has a pending invitation, false otherwise.
    bool invite_pending() const { return invite_status > 0; }

    /// API: groups/member::invite_failed
    ///
    /// Returns true if the user has a pending invitation that is marked as failed (and thus should
    /// be re-sent).
    ///
    /// Inputs: none
    ///
    /// Outputs:
    /// - `bool` -- true if the user has a failed pending invitation
    bool invite_failed() const { return invite_status == INVITE_FAILED; }

    // Flags to track a promoted-to-admin user.  This value is typically not used directly, but
    // rather via the `set_promoted()`, `promotion_pending()` and similar methods.
    int promotion_status = 0;

    /// API: groups/member::set_promoted
    ///
    /// Sets the "promoted" flag for this user.  This marks the user as having a pending
    /// promotion-to-admin in the group.  The optional `failed` parameter can be specified as true
    /// if the promotion was issued but failed to send for some reason (this is intended as a signal
    /// to other clients that the promotion should be reissued).
    ///
    /// Note that this flag is ignored when the `admin` field is set to true.
    ///
    /// Inputs:
    /// - `failed`: can be specified as true to mark the promotion status as "failed-to-send".  If
    ///   omitted or false then the promotion status is set to "sent".
    void set_promoted(bool failed = false) {
        promotion_status = failed ? INVITE_FAILED : INVITE_SENT;
    }

    /// API: groups/member::promotion_pending
    ///
    /// Returns whether the user currently has a pending invitation/promotion to admin status.
    /// Returns true if so (whether or not that invitation has failed).
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `bool` -- true if the user has a pending promotion, false otherwise.
    bool promotion_pending() const { return !admin && promotion_status > 0; }

    /// API: groups/member::promotion_failed
    ///
    /// Returns true if the user has a pending promotion-to-admin that is marked as failed (and thus
    /// should be re-sent).
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `bool` -- true if the user has a failed pending promotion
    bool promotion_failed() const { return !admin && promotion_status == INVITE_FAILED; }

    /// API: groups/member::promoted
    ///
    /// Returns true if the user is already an admin *or* has a pending promotion to admin.
    ///
    /// Inputs: none.
    ///
    /// Outputs:
    /// - `bool` -- true if the member is promoted (or promotion-in-progress)
    bool promoted() const { return admin || promotion_pending(); }

    // Flags to track a removed user.  This value is typically not used directly, but
    // rather via the `set_removed()`, `is_removed()` and similar methods.
    int removed_status = 0;

    /// API: groups/member::set_removed
    ///
    /// Sets the "removed" flag for this user.  This marks the user as pending removal from the
    /// group.  The optional `messages` parameter can be specified as true if we want to remove
    /// any messages sent by the member upon a successful removal.
    ///
    /// Inputs:
    /// - `messages`: can be specified as true to indicate any messages sent by the member
    ///   should also be removed upon a successful member removal.
    void set_removed(bool messages = false) {
        removed_status = messages ? REMOVED_MEMBER_AND_MESSAGES : REMOVED_MEMBER;
    }

    /// API: groups/member::is_removed
    ///
    /// Returns true if the user should be removed from the group.
    ///
    /// Inputs: none.
    ///
    /// Outputs:
    /// - `bool` -- true if the member should be removed from the group
    bool is_removed() const { return removed_status > 0; }

    /// API: groups/member::should_remove_messages
    ///
    /// Returns true if the users messages should be removed after they are
    /// successfully removed.
    ///
    /// Inputs: none.
    ///
    /// Outputs:
    /// - `bool` -- true if the members messages should be removed after they are
    /// successfully removed from the group
    bool should_remove_messages() const { return removed_status == REMOVED_MEMBER_AND_MESSAGES; }

    /// API: groups/member::into
    ///
    /// Converts the member info into a C struct.
    ///
    /// Inputs:
    /// - `m` -- Reference to C struct to fill with group member info.
    void into(config_group_member& m) const;

    /// API: groups/member::set_name
    ///
    /// Sets a name; this is exactly the same as assigning to .name directly, except that we throw
    /// an exception if the given name is longer than MAX_NAME_LENGTH.
    ///
    /// Note that you can set a longer name directly into the `.name` member, but it will be
    /// truncated when serializing the record.
    ///
    /// Inputs:
    /// - `name` -- Name to assign to the contact
    void set_name(std::string name);

  private:
    friend class Members;
    void load(const dict& info_dict);
};

class Members final : public ConfigBase {

  public:
    // No default constructor
    Members() = delete;

    /// API: groups/Members::Members
    ///
    /// Constructs a group members config object from existing data (stored from `dump()`) and a
    /// list of encryption keys for encrypting new and decrypting existing messages.
    ///
    /// To construct a blank members object (i.e. with no pre-existing dumped data to load) pass
    /// `std::nullopt` as the third argument.
    ///
    /// Encryption keys must be loaded before the Members object can be modified or parse other
    /// Members messages, and are typically loaded by providing the `Members` object to the `Keys`
    /// class.
    ///
    /// Inputs:
    /// - `ed25519_pubkey` is the public key of this group, used to validate config messages.
    ///   Config messages not signed with this key will be rejected.
    /// - `ed25519_secretkey` is the secret key of the group, used to sign pushed config messages.
    ///   This is only possessed by the group admin(s), and must be provided in order to make and
    ///   push config changes.
    /// - `dumped` -- either `std::nullopt` to construct a new, empty object; or binary state data
    ///   that was previously dumped from an instance of this class by calling `dump()`.
    Members(ustring_view ed25519_pubkey,
            std::optional<ustring_view> ed25519_secretkey,
            std::optional<ustring_view> dumped);

    /// API: groups/Members::storage_namespace
    ///
    /// Returns the Members namespace. Is constant, will always return Namespace::GroupMembers
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `Namespace` - Will return Namespace::GroupMembers
    Namespace storage_namespace() const override { return Namespace::GroupMembers; }

    /// API: groups/Members::encryption_domain
    ///
    /// Returns the encryption domain used when encrypting messages of this type.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `const char*` - Will return "groups::Members"
    const char* encryption_domain() const override { return "groups::Members"; }

    /// API: groups/Members::get
    ///
    /// Looks up and returns a member by hex session ID.  Returns nullopt if the session ID was
    /// not found, otherwise returns a filled out `member`.
    ///
    /// Inputs:
    /// - `pubkey_hex` -- hex string of the session id
    ///
    /// Outputs:
    /// - `std::optional<member>` - Returns nullopt if session ID was not found, otherwise a
    /// filled out `member` struct.
    std::optional<member> get(std::string_view pubkey_hex) const;

    /// API: groups/Members::get_or_construct
    ///
    /// Similar to get(), but if the session ID does not exist this returns a filled-out member
    /// containing the session_id (all other fields will be empty/defaulted).  This is intended to
    /// be combined with `set` to set-or-create a record.
    ///
    /// NB: calling this does *not* add the session id to the member list when called: that requires
    /// also calling `set` with this value.
    ///
    /// Inputs:
    /// - `pubkey_hex` -- hex string of the session id
    ///
    /// Outputs:
    /// - `member` - Returns a filled out member struct
    member get_or_construct(std::string_view pubkey_hex) const;

    /// API: groups/Members::set
    ///
    /// Sets or updates the various values associated with a member with the given info.   The usual
    /// use is to access the current info, change anything desired, then pass it back into set,
    /// e.g.:
    ///
    /// ```cpp
    ///     auto m = members.get_or_construct(pubkey);
    ///     m.name = "Session User 42";
    ///     members.set(m);
    /// ```
    ///
    /// Inputs:
    /// - `member` -- member value to set
    void set(const member& member);

    /// API: groups/Members::erase
    ///
    /// Removes a session ID from the member list, if present.
    ///
    /// Typically this call should be coupled with a re-key of the group's encryption key so that
    /// the removed member cannot read the group.  For example:
    ///
    ///     bool removed = members.erase("050123456789abcdef...");
    ///     // You can remove more than one at a time, if needed:
    ///     removed |= members.erase("050000111122223333...");
    ///
    ///     if (removed) {
    ///         auto new_keys_conf = keys.rekey(info, members);
    ///         auto [members_seqno, new_memb_conf, members_obs] = members.push();
    ///         auto [info_seqno, new_info_conf, info_obs] = info.push();
    ///
    ///         // Send the three new configs to the swarm (via a sequence of three `store`s):
    ///         // - new_keys_conf goes into the keys namespace
    ///         // - new_memb_conf goes into the members namespace
    ///         // - new_info_conf goes into the info namespace
    ///     }
    ///
    /// Inputs:
    /// - `session_id` the hex session ID of the member to remove
    ///
    /// Outputs:
    /// - true if the member was found (and removed); false if the member was not in the list.
    bool erase(std::string_view session_id);

    /// API: groups/Members::size
    ///
    /// Returns the number of members in the group.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `size_t` - number of members
    size_t size() const;

    struct iterator;
    /// API: groups/Members::begin
    ///
    /// Iterators for iterating through all members.  Typically you access this implicit via a for
    /// loop over the `Members` object:
    ///
    ///```cpp
    ///     for (auto& member : members) {
    ///         // use member.session_id, member.name, etc.
    ///     }
    ///```
    ///
    /// This iterates in sorted order through the session_ids.
    ///
    /// It is NOT permitted to add/modify/remove records while iterating; instead such modifications
    /// require two passes: an iterator loop to collect the required modifications, then a second
    /// pass to apply the modifications.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `iterator` - Returns an iterator for the beginning of the members
    iterator begin() const { return iterator{data["m"].dict()}; }

    /// API: groups/Members::end
    ///
    /// Iterator for passing the end of the members
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `iterator` - Returns an iterator for the end of the members
    iterator end() const { return iterator{nullptr}; }

    using iterator_category = std::input_iterator_tag;
    using value_type = member;
    using reference = value_type&;
    using pointer = value_type*;
    using difference_type = std::ptrdiff_t;

    struct iterator {
      private:
        std::shared_ptr<member> _val;
        dict::const_iterator _it;
        const dict* _members;
        void _load_info();
        iterator(const dict* members) : _members{members} {
            if (_members) {
                _it = _members->begin();
                _load_info();
            }
        }
        friend class Members;

      public:
        bool operator==(const iterator& other) const;
        bool operator!=(const iterator& other) const { return !(*this == other); }
        bool done() const;  // Equivalent to comparing against the end iterator
        member& operator*() const { return *_val; }
        member* operator->() const { return _val.get(); }
        iterator& operator++();
        iterator operator++(int) {
            auto copy{*this};
            ++*this;
            return copy;
        }
    };
};

}  // namespace session::config::groups
