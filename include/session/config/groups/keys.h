#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "../../state.h"
#include "../util.h"

/// API: groups/state_size_group_keys
///
/// Returns the number of decryption keys stored in this Keys object.  Mainly for
/// debugging/information purposes.
///
/// Inputs:
/// - `state` -- [in] - Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
///
/// Outputs:
/// - `size_t` -- number of members in the group (will be 0 if the group doesn't exist or the
/// 'pubkey_hex' is invalid)
LIBSESSION_EXPORT size_t state_size_group_keys(const state_object* state, const char* group_id);

/// API: groups/state_get_group_key
///
/// Accesses the Nth encryption key, ordered from most-to-least recent starting from index 0.
/// Calling this with 0 thus returns the most-current key (which is also the current _en_cryption
/// key).
///
/// This function is not particularly efficient and is not typically needed except for diagnostics:
/// instead encryption/decryption should be performed used the dedicated functions which
/// automatically manage the decryption keys.
///
/// This function can be used to obtain all decryption keys by calling it with an incrementing value
/// until it returns nullptr (or alternatively, looping over `0 <= i < groups_keys_size`).
///
/// Returns nullptr if N is >= the current number of decryption keys.
///
/// The returned pointer points at a 32-byte binary value containing the key; it should be copied or
/// used at once as it may not remain valid past other calls to the keys object.  It should *not* be
/// freed.
///
/// Inputs:
/// - `state` -- Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `N` -- the index of the key to obtain
///
/// Outputs:
/// - `const unsigned char*` -- pointer to the 32-byte key, or nullptr if thereis no group or key
LIBSESSION_EXPORT const unsigned char* state_get_group_key(
        const state_object* state, const char* group_id, size_t N);
//
/// API: groups/state_is_group_admin
///
/// Returns true if this object has the group private keys, i.e. the user is an all-powerful
/// wiz^H^H^Hadmin of the group.
///
/// Inputs:
/// - `state` -- Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
///
/// Outputs:
/// - `true` if we have admin keys, `false` otherwise.
LIBSESSION_EXPORT bool state_is_group_admin(const state_object* state, const char* group_id);

/// API: groups/state_load_group_admin_key
///
/// Loads the admin keys, effectively upgrading this keys object from a member to an admin.
///
/// This does nothing if the keys object already has admin keys.
///
/// Inputs:
/// - `state` -- Pointer to the mutable state object
/// - `secret` -- pointer to the 32-byte group seed.  (This a 64-byte libsodium "secret key" begins
///   with the seed, this can also be a given a pointer to such a value).
///
/// Outputs:
/// - `true` if the object has been upgraded to admin status, or was already admin status; `false`
///   if the given seed value does not match the group's public key.  If this returns `true` then
///   after the call a call to `state_is_group_admin` would also return `true`.
LIBSESSION_EXPORT bool state_load_group_admin_key(
        mutable_group_state_object* state, const unsigned char* secret);

/// API: groups/state_group_needs_rekey
///
/// Checks whether a rekey is required (for instance, because of key generation conflict).  Note
/// that this is *not* a check for when members changed (such rekeys are up to the caller to
/// manage), but mergely whether a rekey is needed after loading one or more config messages.
///
/// See the C++ Keys::needs_rekey and Keys::rekey descriptions for more details.
///
/// Inputs:
/// - `state` -- Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
///
/// Outputs:
/// - `bool` -- `true` if `rekey()` needs to be called, `false` otherwise.
LIBSESSION_EXPORT bool state_group_needs_rekey(const state_object* state, const char* group_id)
        __attribute__((warn_unused_result));

/// API: groups/state_rekey_group
///
/// Generates a new encryption key for the group containing the key, encrypted for the members of
/// the group. This function should be used after modify group members when mutating a group to
/// ensure the updated keys include the changes.
///
/// See Keys::rekey in the C++ API for more details about intended use.
///
/// Inputs:
/// - `state` -- Pointer to the mutable state object
///
/// Output:
/// - `bool` -- Returns true on success, false on failure.
LIBSESSION_EXPORT bool state_rekey_group(mutable_group_state_object* state)
        __attribute__((warn_unused_result));

/// API: groups/state_supplement_group_key
///
/// Generates a supplemental key message for one or more session IDs.  This is used to distribute
/// existing active keys to a new member so that that member can access existing keys, configs, and
/// messages.  Only admins can call this.
///
/// The recommended order of operations for adding such a member is:
/// - add the member to Members
/// - generate the key supplement
/// - push new members & key supplement (ideally in a batch)
/// - send invite details, auth signature, etc. to the new user
///
/// To add a member *without* giving them access to old messages you would use groups_keys_rekey()
/// instead of this method.
///
/// Inputs:
/// - `state` -- [in] - Pointer to the mutable state object
/// - `sids` -- array of session IDs of the members to generate a supplemental key for; each element
///   must be an ordinary (null-terminated) C string containing the 66-character session id.
/// - `sids_len` -- length of the `sids` array
/// - `callback` -- [in] Callback function called once the send process completes
/// - `ctx` --- [in, optional] Pointer to an optional context. Set to NULL if unused
LIBSESSION_EXPORT void state_supplement_group_key(
        mutable_group_state_object* state,
        const char** sids,
        size_t sids_len,
        void (*callback)(
                bool success,
                int16_t status_code,
                const unsigned char* res,
                size_t reslen,
                void* ctx),
        void* ctx);

/// API: groups/state_get_current_group_generation
///
/// Returns the current generation number for the latest keys message.
///
/// Inputs:
/// - `state` -- [in] - Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
///
/// Oututs:
/// - `int` -- latest keys generation number, returns 0 if there is no group or the key is invalid
LIBSESSION_EXPORT int state_get_current_group_generation(
        const state_object* state, const char* group_id);

/// API: groups/state_make_group_swarm_subaccount
///
/// Constructs a swarm subaccount signing value that a member can use to access messages in the
/// swarm.  The member will have read and write access, but not delete access.  Requires group
/// admins keys.
///
/// Inputs:
/// - `state` -- [in] - Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `session_id` -- the session ID of the member (in hex)
/// - `sign_value` -- [out] pointer to a 100 byte (or larger) buffer where the 100 byte signing
///   value will be written.  This is the value that should be sent to a member to allow
///   authentication.
///
/// Outputs:
/// - `true` -- if making the subaccount succeeds, false if it fails (e.g. because of an invalid
///   session id, or not being an admin).  If a failure occurs, sign_value will not be written to.
LIBSESSION_EXPORT bool state_make_group_swarm_subaccount(
        const state_object* state,
        const char* group_id,
        const char* session_id,
        unsigned char* sign_value,
        char* error);

/// API: groups/state_make_group_swarm_subaccount_flags
///
/// Same as state_make_group_swarm_subaccount, but lets you specify whether the write/del flags are
/// present.
///
/// Inputs:
/// - `state` -- [in] - Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `session_id` -- the member session id (hex c string)
/// - `write` -- if true then the member shall be allowed to submit messages into the group account
///   of the swarm and extend (but not shorten) the expiry of messages in the group account.  If
///   false then the user can only retrieve messages.  Typically this is true.
/// - `del` -- if true (default is false) then the user shall be allowed to delete messages from the
///   swarm.  This permission can be used to appoint a sort of "moderator" who can delete messages
///   without having the full admin group keys.  Typically this is false.
/// - `sign_value` -- pointer to a buffer with at least 100 bytes where the 100 byte signing value
///   will be written.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `bool` - same as state_make_group_swarm_subaccount
LIBSESSION_EXPORT bool state_make_group_swarm_subaccount_flags(
        const state_object* state,
        const char* group_id,
        const char* session_id,
        bool write,
        bool del,
        unsigned char* sign_value,
        char* error);

/// API: groups/verify_group_swarm_subaccount
///
/// Verifies that a received subaccount signing value (allegedly produced by
/// groups_keys_swarm_make_subaccount) is a valid subaccount signing value for the given group
/// pubkey, including a proper signature by an admin of the group.  The signing value must have read
/// permission, but parameters can be given to also require write or delete permissions.  A
/// subaccount signing value should always be checked for validity using this before creating a
/// group that would depend on it.
///
/// Inputs:
/// - note that this function does *not* take a config object as it is intended for use to validate
///   an invitation before constructing the keys config objects.
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `session_ed25519_secretkey` -- the user's Session ID secret key (64 bytes).
/// - `signing_value` -- the 100-byte subaccount signing value to validate
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// The key will require read and write access to be acceptable.  (See the _flags version if you
/// need something else).
///
/// Outputs:
/// - `true` if `signing_value` is a valid subaccount signing value for `groupid` with (at least)
///   read and write permissions, `false` if the signing value does not validate or does not meet
///   the requirements.
LIBSESSION_EXPORT bool verify_group_swarm_subaccount(
        const char* group_id,
        const unsigned char* session_ed25519_secretkey,
        const unsigned char* signing_value);

/// API: groups/verify_group_swarm_subaccount_flags
///
/// Same as verify_group_swarm_subaccount, except that you can specify whether you want to
/// require the write and or delete flags.
///
/// Inputs:
/// - same as verify_group_swarm_subaccount
/// - `write` -- if true, require that the signing_value has write permission (i.e. that the
///   user will be allowed to post messages).
/// - `del` -- if true, required that the signing_value has delete permissions (i.e. that the
///   user will be allowed to remove storage messages from the group's swarm).  Note that this
///   permission is about forcible swarm message deletion, and has no effect on an ability to
///   submit a deletion meta-message to the group (which only requires writing a message).
LIBSESSION_EXPORT bool verify_group_swarm_subaccount_flags(
        const char* group_id,
        const unsigned char* session_ed25519_secretkey,
        const unsigned char* signing_value,
        bool write,
        bool del);

/// API: groups/state_sign_group_swarm_subaccount
///
/// This helper function generates the required signature for swarm subaccount authentication,
/// given the user's keys and swarm auth keys (as provided by an admin, produced via
/// `state_make_group_swarm_subaccount`).
///
/// Storage server subaccount authentication requires passing the three values in the returned
/// struct in the storage server request.
///
/// This version of the function writes base64-encoded values to the output parameters; there is
/// also a `_binary` version that writes raw values.
///
/// Inputs:
/// - `state` -- Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `msg` -- the binary data that needs to be signed (which depends on the storage server request
///   being made; for example, "retrieve9991234567890123" for a retrieve request to namespace 999
///   made at unix time 1234567890.123; see storage server RPC documentation for details).
/// - `msg_len` -- the length of the `msg` buffer
/// - `signing_value` -- the 100-byte subaccount signing value, as produced by an admin's
///   `swarm_make_subaccount` and provided to this member.
/// - `subaccount` -- [out] a C string buffer of *at least* 49 bytes where the null-terminated
///   48-byte base64-encoded subaccount value will be written.  This is the value to pass as
///   `subaccount` for storage server subaccount authentication.
/// - `subaccount_sig` -- [out] a C string buffer of *at least* 89 bytes where the null-terminated,
///   88-ascii-character base64-encoded version of the 64-byte admin signature authorizing this
///   subaccount will be written.  This is the value to be passed as `subaccount_sig` for storage
///   server subaccount authentication.
/// - `signature` -- [out] a C string buffer of *at least* 89 bytes where the null-terminated,
///   88-character request signature will be written, base64 encoded.  This is passes as the
///   `signature` value, alongside `subaccount`/`subaccoung_sig` to perform subaccount signature
///   authentication.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - true if the values were written, false if an error occured (e.g. from an invalid signing_value
///   or cryptography error).
LIBSESSION_EXPORT bool state_sign_group_swarm_subaccount(
        const state_object* state,
        const char* group_id,
        const unsigned char* msg,
        size_t msg_len,
        const unsigned char* signing_value,

        char* subaccount,
        char* subaccount_sig,
        char* signature,
        char* error);

/// API: groups/state_sign_group_swarm_subaccount_binary
///
/// Does exactly the same as state_sign_group_swarm_subaccount except that the subaccount,
/// subaccount_sig, and signature values are written in binary (without null termination) of exactly
/// 36, 64, and 64 bytes, respectively.
///
/// Inputs:
/// - see state_sign_group_swarm_subaccount
/// - `subaccount`, `subaccount_sig`, and `signature` are binary output buffers of size 36, 64, and
///   64, respectively.
///
/// Outputs:
/// See groups_keys_swarm_subaccount.
LIBSESSION_EXPORT bool state_sign_group_swarm_subaccount_binary(
        const state_object* state,
        const char* group_id,
        const unsigned char* msg,
        size_t msg_len,
        const unsigned char* signing_value,

        unsigned char* subaccount,
        unsigned char* subaccount_sig,
        unsigned char* signature,
        char* error);

/// API: groups/state_get_group_swarm_subaccount_token
///
/// Constructs the subaccount token for a session id.  The main use of this is to submit a swarm
/// token revocation; for issuing subaccount tokens you want to use
/// `groups_keys_swarm_make_subaccount` instead.  This will produce the same subaccount token that
/// `groups_keys_swarm_make_subaccount` implicitly creates that can be passed to a swarm to add a
/// revocation for that subaccount.
///
/// This is recommended to be used when removing a non-admin member to prevent their access.
/// (Note, however, that there are circumstances where this can fail to prevent access, and so
/// should be combined with proper member removal and key rotation so that even if the member
/// gains access to messages, they cannot read them).
///
/// Inputs:
/// - `state` -- Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `session_id` -- the session ID of the member (in hex)
/// - `token` -- [out] a 36-byte buffer into which to write the subaccount token.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - true if the call succeeded, false if an error occured.
LIBSESSION_EXPORT bool state_get_group_swarm_subaccount_token(
        const state_object* state,
        const char* group_id,
        const char* session_id,
        unsigned char* token,
        char* error);

/// API: groups/state_get_group_swarm_subaccount_token_flags
///
/// Same as `state_get_group_swarm_subaccount_token`, but takes `write` and `del` flags for creating
/// a token matching a user with non-standard permissions.
///
/// Inputs:
/// - `state` -- Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `session_id` -- the session ID of the member (in hex)
/// - `write`, `del` -- see groups_keys_swarm_make_subaccount_flags
/// - `token` -- [out] a 36-byte buffer into which to write the subaccount token.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - true if the call succeeded, false if an error occured.
LIBSESSION_EXPORT bool state_get_group_swarm_subaccount_token_flags(
        const state_object* state,
        const char* group_id,
        const char* session_id,
        bool write,
        bool del,
        unsigned char* token,
        char* error);

/// API: groups/state_encrypt_group_message
///
/// Encrypts a message using the most recent group encryption key of this object.
///
/// The message will be compressed (if that reduces the size), padded, authored, and signed before
/// being encrypted.  Decryption and verification (and decompression, if compression was applied) is
/// performed by passing such a message into groups_keys_decrypt_message.
///
/// Note: this method can fail if there are no encryption keys at all, or if the incoming message
/// decompresses to a huge value (more than 1MB).  If it fails then `ciphertext_out` is set to NULL
/// and should not be read or free()d.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- [in] the group id/pubkey, in hex, beginning with "03".
/// - `plaintext_in` -- [in] Pointer to a data buffer containing the unencrypted data.
/// - `plaintext_len` -- [in] Length of `plaintext_in`
/// - `ciphertext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   encrypted data written to it, and then the pointer to that buffer is stored here.  This
///   buffer must be `free()`d by the caller when done with it!
/// - `ciphertext_len` -- [out] Pointer to a size_t where the length of `ciphertext_out` is stored.
LIBSESSION_EXPORT void state_encrypt_group_message(
        const state_object* state,
        const char* group_id,
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len);

/// API: groups/state_decrypt_group_message
///
/// Attempts to decrypt a message using all of the known active encryption keys of this object.  The
/// message will be de-padded, decompressed (if compressed), and have its signature verified after
/// decryption.
///
/// Upon failure this returns false and sets `conf.last_error` to a string containing a diagnostic
/// reason the decryption failed (intended for logging, not for end-user display).
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- [in] the group id/pubkey, in hex, beginning with "03".
/// - `ciphertext_in` -- [in] Pointer to a data buffer containing the encrypted data (as was
///   produced by `groups_keys_encrypt_message`).
/// - `ciphertext_len` -- [in] Length of `ciphertext_in`
/// - `session_id_out` -- [out] pointer to a buffer of at least 67 bytes where the null-terminated,
///   hex-encoded session_id of the message's author will be written if decryption/verification was
///   successful.
/// - `plaintext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   decrypted/decompressed data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `plaintext_len` -- [out] Pointer to a size_t where the length of `plaintext_out` is stored.
///   Not touched if the function returns false.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `bool` -- True if the message was successfully decrypted, false if decryption (or parsing or
///   decompression) failed with all of our known keys.  If (and only if) true is returned then
///   `plaintext_out` must be freed when done with it.  If false is returned then `conf.last_error`
///   will contain a diagnostic message describing why the decryption failed.
LIBSESSION_EXPORT bool state_decrypt_group_message(
        const state_object* state,
        const char* group_id,
        const unsigned char* cipherext_in,
        size_t cipherext_len,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len,
        char* error);

#ifdef __cplusplus
}  // extern "C"
#endif
