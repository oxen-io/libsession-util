#pragma once

#include <chrono>
#include <memory>

#include "../../config.hpp"
#include "../base.hpp"
#include "../namespaces.hpp"
#include "../profile_pic.hpp"
#include "members.hpp"

namespace session::config::groups {

class Members;
class Info;

using namespace std::literals;

/// This "config" isn't exactly a regular config type that inherits from ConfigBase; in particular:
/// - it doesn't encrypt the message (but merely contains encrypted elements within it)
/// - it doesn't merge
/// - it does have a concept analogous to the message seqno
/// - conflict resolution involves regenerating and distributing new keys; nothing gets merged.
/// - it cares strongly about when new configs were pushed (configs expire after having been
///   replaced for a certain amount of time, not by being updated).
/// - its internal state isn't fully serialized when pushing updates
/// - messages don't contain the outer layer of config messages (where config metadata, references
///   to other objects, etc.) that ConfigBase-derived type hold.
/// - it isn't compressed (since most of the data fields are encrypted or random, compression
///   reduction would be minimal).
///
/// Fields used (in ascii order):
/// # -- 24-byte nonce used for all the encrypted values in this message; required.
/// + -- set to 1 if this is a supplemental key message; omitted for a full key message.  (It's
///      important that this key sort earlier than any fields that can differ between
///      supplemental/non-supplemental fields so we can identify the message type while parsing it).
/// G -- monotonically incrementing counter identifying key generation changes
/// K -- encrypted copy of the key for admins (omitted for `+` incremental key messages)
/// k -- packed bytes of encrypted keys for non-admin members; this is a single byte string in which
///      each 48 bytes is a separate encrypted value.
/// ~ -- signature of the message signed by the group's master keypair, signing the message value up
///      to but not including the ~ keypair.  The signature must be the last key in the dict (thus
///      `~` since it is the largest 7-bit ascii character value).  Note that this signature
///      mechanism works exactly the same as the signature on regular config messages.
///
/// Some extra details:
///
/// - each copy of the encryption key uses xchacha20_poly1305 using the `n` nonce
/// - the `k` members list gets padded with junk entries up to the next multiple of 75 (for
///   non-supplemental messages).
/// - the decryption key for the admin version of the key is H(admin_seed,
///   key="SessionGroupKeyAdmin")
/// - the encryption key for a member is H(a'B || A' || B, key="SessionGroupKeyMember") where a'/A'
///   is the group Ed25519 master key converted to X25519, and b/B is the member's X25519 keypair
///   (i.e. B is the non-05-prefixed session_id).
///   - the decryption key is calculated by the member using `bA' || A' || B`
/// - A new key and nonce is created from a 56-byte H(M0 || M1 || ... || Mn || g || S,
///   key="SessionGroupKeyGen"), where S = H(group_seed, key="SessionGroupKeySeed").

class Keys final : public ConfigSig {

    Ed25519Secret user_ed25519_sk;

    struct key_info {
        std::array<unsigned char, 32> key;
        std::chrono::system_clock::time_point timestamp; // millisecond precision
        int64_t generation;

        auto cmpval() const { return std::tie(generation, timestamp, key); }
        bool operator<(const key_info& b) const { return cmpval() < b.cmpval(); }
        bool operator>(const key_info& b) const { return cmpval() > b.cmpval(); }
        bool operator<=(const key_info& b) const { return cmpval() <= b.cmpval(); }
        bool operator>=(const key_info& b) const { return cmpval() >= b.cmpval(); }
        bool operator==(const key_info& b) const { return cmpval() == b.cmpval(); }
        bool operator!=(const key_info& b) const { return cmpval() != b.cmpval(); }
    };

    /// Vector of keys that is kept sorted by generation/timestamp/key.  This gets pruned as keys
    /// have been superceded by another key for a sufficient amount of time (see KEY_EXPIRY).
    sodium_vector<key_info> keys_;

    sodium_cleared<std::array<unsigned char, 32>> pending_key_;
    sodium_vector<unsigned char> pending_key_config_;
    int64_t pending_gen_ = -1;

    bool needs_dump_ = false;

    ConfigMessage::verify_callable verifier_;
    ConfigMessage::sign_callable signer_;

    void set_verifier(ConfigMessage::verify_callable v) override { verifier_ = std::move(v); }
    void set_signer(ConfigMessage::sign_callable s) override { signer_ = std::move(s); }

    // Checks for and drops expired keys.
    void remove_expired();

    // Loads existing state from a previous dump of keys data
    void load_dump(ustring_view dump);

  public:
    /// The multiple of members keys we include in the message; we add junk entries to the key list
    /// to reach a multiple of this.  75 is chosen because it's a decently large human-round number
    /// that should still fit within 4kiB page size on the storage server (allowing for some extra
    /// row field storage).
    static constexpr int MESSAGE_KEY_MULTIPLE = 75;

    // 75 because:
    // 2              // for the 'de' delimiters of the outer dict
    // + 3 + 2 + 12   // for the `1:g` and `iNNNNNNNNNNe` generation keypair
    // + 3 + 3 + 24   // for the `1:n`, `24:`, and 24 byte nonce
    // + 3 + 3 + 48   // for the `1:K`, `48:`, and 48 byte ciphertexted key
    // + 3 + 6        // for the `1:k` and `NNNNN:` key and prefix of the keys pair
    // + N * 48       // for the packed encryption keys
    // + 3 + 3 + 64;  // for the `1:~` and `64:` and 64 byte signature
    // = 177 + 48N
    //
    // and N=75 puts us a little bit under 4kiB (which is sqlite's default page size).

    /// A key expires when it has been surpassed by another key for at least this amount of time.
    /// We default this to double the 30 days that we strictly need to avoid race conditions with
    /// 30-day old config messages that might need the key for a client that is only very rarely
    /// online.
    static constexpr auto KEY_EXPIRY = 2 * 30 * 24h;

    // No default constructor
    Keys() = delete;

    /// API: groups/Keys::Keys
    ///
    /// Constructs a group members config object from existing data (stored from `dump()`) and a
    /// list of encryption keys for encrypting new and decrypting existing messages.
    ///
    /// To construct a blank info object (i.e. with no pre-existing dumped data to load) pass
    /// `std::nullopt` as the last argument.
    ///
    /// Inputs:
    /// - `user_ed25519_secretkey` is the ed25519 secret key backing the current user's session ID,
    ///   and is used to decrypt incoming keys.  It is required.
    /// - `group_ed25519_pubkey` is the public key of the group, used to verify message signatures
    ///   on key updates.  Required.  Should not include the `03` prefix.
    /// - `group_ed25519_secretkey` is the secret key of the group, used to encrypt, decrypt, and
    ///   sign config messages.  This is only possessed by the group admin(s), and must be provided
    ///   in order to make and push config changes.
    /// - `dumped` -- either `std::nullopt` to construct a new, empty object; or binary state data
    ///   that was previously dumped from an instance of this class by calling `dump()`.
    /// - `info` and `members` -- will be loaded with the group keys, if present in the dump.
    ///   Otherwise, if this is an admin Keys object, with a new one constructed for the initial
    ///   Keys object; or with no keys loaded at all if this is a non-admin, non-dump construction.
    ///   (Keys will also be loaded later into this and the info/members objects, when rekey()ing or
    ///   loading keys via received config messages).
    Keys(ustring_view user_ed25519_secretkey,
         ustring_view group_ed25519_pubkey,
         std::optional<ustring_view> group_ed25519_secretkey,
         std::optional<ustring_view> dumped,
         Info& info,
         Members& members);

    /// API: groups/Keys::storage_namespace
    ///
    /// Returns the Keys namespace. Is constant, will always return Namespace::GroupKeys
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `Namespace` - Will return Namespace::GroupKeys
    Namespace storage_namespace() const { return Namespace::GroupKeys; }

    /// API: groups/Keys::encryption_domain
    ///
    /// Returns the encryption domain used when encrypting messages of this type.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `const char*` - Will return "groups::Keys"
    const char* encryption_domain() const { return "groups::Keys"; }

    /// API: groups/Keys::group_keys
    ///
    /// Returns all the unexpired decryption keys that we know about.  Keys are returned ordered
    /// from most-recent to least-recent (and so the first one is meant to be used as the encryption
    /// key), including a pending key if this object is in the process of pushing a new keys
    /// message.
    ///
    /// This isn't typically directly needed: this object manages the key lists in the `info` and
    /// `members` objects itself.
    ///
    /// Inputs: none.
    ///
    /// Outputs:
    /// - `std::vector<ustring_view>` - vector of encryption keys.
    std::vector<ustring_view> group_keys() const;

    /// API: groups/Keys::rekey
    ///
    /// Generate a new encryption key for the group and returns an encrypted key message to be
    /// pushed to the swarm containing the key, encrypted for the members of the given
    /// config::groups::Members object.  This can only be done by an admin account (i.e. we must
    /// have the group's private key).
    ///
    /// This method is intended to be called in two situations:
    /// - potentially after loading new keys config messages (see `needs_rekey()`)
    /// - when removing a member to switch to a new encryption key for the group that excludes that
    ///   member.
    ///
    /// This method is closely coupled to the group's Info and Members configs: it updates their
    /// encryption keys and sets them as dirty, requiring a re-push to re-encrypt each of them.
    /// Typically a rekey is performed as follows:
    ///
    /// - `rekey()` is called, returning the new keys config.
    /// - `info.push()` is called to get the new info config (re-encrypted with the new key)
    /// - `members.push()` is called to get the new members config (using the new key)
    /// - all three new configs are pushed (ideally all at once, in a single batch request).
    ///
    /// Inputs:
    /// - `Info` - the group's Info; it will be dirtied after the rekey and will require a push.
    /// - `Members` - the current Members config for the group.  When removing one or more members
    ///   this should be the list of members with the specific members already removed.  The members
    ///   config will be dirtied after the rekey and will require a push.
    ///
    /// Outputs:
    /// - `ustring_view` containing the data that needs to be pushed to the config keys namespace
    ///   for the group.  (This can be re-obtained from `push()` if needed until it has been
    ///   confirmed or superceded).
    ustring_view rekey(Info& info, Members& members);

    /// API: groups/Keys::pending_push
    ///
    /// If a rekey has been performed but not yet confirmed then this will contain the config
    /// message to be pushed to the swarm.  If there is no push current pending then this returns
    /// nullopt.  The value should be used immediately (i.e. the ustring_view may not remain valid
    /// if other calls to the config object are made).
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::optional<ustring_view>` -- returns a populated config message that should be pushed,
    ///   if not yet confirmed, otherwise when no pending update is present this returns nullopt.
    std::optional<ustring_view> pending_config() const;

    /// API: groups/Keys::pending_key
    ///
    /// After calling rekey() this contains the new group encryption key *before* it is confirmed
    /// pushed into the swarm.  This is primarily used to allow a rekey + member list update using
    /// the new key in the same swarm upload sequence.
    ///
    /// The pending key is dropped when an incoming keys message is successfully loaded with either
    /// the pending key itself, or a keys message with a higher generation.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `std::optional<ustring_view>` the encryption key generated by the last `rekey()` call.
    ///   This is set to a new key when `rekey()` is called, and is cleared when any config message
    ///   is successfully loaded by `load_key`.
    std::optional<ustring_view> pending_key() const;

    /// API: groups/Keys::load_key
    ///
    /// Loads a key pulled down from the swarm into this Keys object.
    ///
    /// A Session client must process messages from the keys namespace *before* other group config
    /// messages as new key messages may contain encryption keys needed to decrypt the other group
    /// config message types.
    ///
    /// It is safe to load the same config multiple times, and to load expired configs; such cases
    /// would typically not change the keys, but are allowed anyway.
    ///
    /// This method should always be wrapped in a `try/catch`: if the given configuration data is
    /// malformed or is not properly signed an exception will be raised (but the Keys object remains
    /// usable).
    ///
    /// Inputs:
    /// - `msg` - the full stored config message value
    /// - `hash` - the storage message hash (used to track current config messages)
    /// - `timestamp` - the timestamp (from the swarm) when this message was stored (used to track
    ///   when other keys expire).
    /// - `members` - the given group::Members object's en/decryption key list will be updated to
    ///   match this object's key list.
    /// - `info` - the given group::Info object's en/decryption key list will be updated to match
    ///   this object's key list.
    ///
    /// Outputs:
    /// - throws `std::runtime_error` (typically a subclass thereof) on failure to parse.
    void load_key_message(
            ustring_view data,
            ustring_view msgid,
            int64_t timestamp_ms,
            Info& info,
            Members& members);

    /// API: groups/Keys::needs_rekey
    ///
    /// Returns true if the key list requires a new key to be generated and pushed to the server (by
    /// calling `rekey()`).  This will only be true for admin accounts (as only admin accounts can
    /// call rekey()).  Note that this value will also remain true until the pushed data is fetched
    /// and loaded via `load_key_message`.
    ///
    /// Note that this not only tracks when an automatic `rekey()` is needed because of a key
    /// collision (such as two admins removing different members at the same time); there are other
    /// situations in which rekey() should also be called (such as when kicking a member) that are
    /// not reflected by this flag.
    ///
    /// The recommended use of this method is to call it immediately after fetching messages from
    /// the group config namespace of the swarm, whether or not new configs were retrieved, but
    /// after processing incoming new config messages that were pulled down.
    ///
    /// Unlike regular config messages, there is no need to confirm the push: confirmation (and
    /// adoption of the new keys) happens when the new keys arrived back down from the swarm in the
    /// next fetch.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `true` if a rekey is needed, `false` otherwise.
    bool needs_rekey() const;

    /// API: groups/Keys::needs_dump
    ///
    /// Returns true if this Keys config has changes, either made directly or from incoming configs,
    /// that need to be dumped to the database (made since the last call to `dump()`), false if no
    /// changes have been made.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - `true` if state needs to be dumped, `false` if state hasn't changed since the last
    ///   call to `dump()`.
    bool needs_dump() const;

    /// API: groups/Keys::dump
    ///
    /// Returns a dump of the current state of this keys config that allows the Keys object to be
    /// reinstantiated from scratch.
    ///
    /// Although this can be called at any time, it is recommended to only do so when
    /// `needs_dump()` returns true.
    ///
    /// Inputs: None
    ///
    /// Outputs:
    /// - opaque binary data containing the group keys and other Keys config data that can be passed
    ///   to the `Keys` constructor to reinitialize a Keys object with the current state.
    ustring dump();
};

}  // namespace session::config::groups
