#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "../base.h"
#include "../util.h"

// This is an opaque type analagous to `config_object` but specific to the groups keys object.
//
// It is constructed via groups_keys_init and destructed via groups_keys_free.
typedef struct config_group_keys {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;

    // When an error occurs in the C API this string will be set to the specific error message.  May
    // be empty.
    const char* last_error;

    // Sometimes used as the backing buffer for `last_error`.  Should not be touched externally.
    char _error_buf[256];

} config_group_keys;

/// API: groups/groups_keys_init
///
/// Constructs a group keys management config object and sets a pointer to it in `conf`.
///
/// Note that this is *not* a regular `config_object` and thus does not use the usual
/// `config_free()` and similar methods from `session/config/base.h`; instead it must be managed by
/// the functions declared in the header.
///
/// Inputs:
/// - `conf` -- [out] Pointer-pointer to a `config_group_keys` pointer (i.e. double pointer); the
///   pointer will be set to a new config_group_keys object on success.
///
///   Intended use:
///
///   ```C
///   config_group_keys* keys;
///   int rc = groups_keys_init(&keys, ...);
///   ```
/// - `user_ed25519_secretkey` -- [in] 64-byte pointer to the **user**'s (not group's) secret
///   ed25519 key.  (Used to be able to decrypt keys encrypted individually for us).
/// - `group_ed25519_pubkey` -- [in] 32-byte pointer to the group's public key
/// - `group_ed25519_secretkey` -- [in] optional 64-byte pointer to the group's secret key
///   (libsodium-style 64 byte value).  Pass as NULL for a non-admin member.
/// - `group_info_conf` -- the group info config instance (keys will be added)
/// - `group_members_conf` -- the group members config instance (keys will be added)
/// - `dump` -- [in] if non-NULL this restores the state from the dumped byte string produced by a
///   past instantiation's call to `dump()`.  To construct a new, empty object this should be NULL.
/// - `dumplen` -- [in] the length of `dump` when restoring from a dump, or 0 when `dump` is NULL.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
///   occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
///   buffer of at least 256 bytes.
///
/// Outputs:
/// - `int` -- Returns 0 on success; returns a non-zero error code and write the exception message
/// as a C-string into `error` (if not NULL) on failure.
LIBSESSION_EXPORT int groups_keys_init(
        config_group_keys** conf,
        const unsigned char* user_ed25519_secretkey,
        const unsigned char* group_ed25519_pubkey,
        const unsigned char* group_ed25519_secretkey,
        config_object* group_info_conf,
        config_object* group_members_conf,
        const unsigned char* dump,
        size_t dumplen,
        char* error) __attribute__((warn_unused_result));

/// API: groups/groups_keys_rekey
///
/// Generates a new encryption key for the group and returns an encrypted key message to be pushed
/// to the swarm containing the key, encrypted for the members of the group.
///
/// The returned binary key message to be pushed is written into a newly-allocated buffer.  A
/// pointer to this buffer is set in the pointer-pointer `out` argument, and its length is set in
/// the `outlen` pointer.
///
/// See Keys::rekey in the C++ API for more details about intended use.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `info` -- [in] Pointer to group Info object
/// - `members` -- [in] Pointer to group Members object
/// - `out` -- [out] Will be set to a pointer to the message to be pushed (only if the function
///   returns true).  This value must be used immediately (it is not guaranteed to remain valid
///   beyond other calls to the config object), and must not be freed (i.e. ownership remains with
///   the keys config object).
/// - `outlen` -- [out] Length of the output value.  Only set when the function returns true.
///
/// Output:
/// - `bool` -- Returns true on success, false on failure.
LIBSESSION_EXPORT bool groups_keys_rekey(
        config_group_keys* conf,
        config_object* info,
        config_object* members,
        const unsigned char** out,
        size_t* outlen) __attribute__((warn_unused_result));

/// API: groups/groups_keys_pending_config
///
/// If a `rekey()` is currently in progress (and not yet confirmed, or possibly lost), this returns
/// the config message that should be pushed.  As with the result of `rekey()` the pointer ownership
/// remains with the keys config object, and the value should be used/copied immediately.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `out` -- [out] Pointer-pointer that will be updated to point at the config data.  Only set if
///   this function returns true!
/// - `outlen` -- [out] Pointer to the config data size (only set if the function returns true).
///
/// Outputs:
/// - `bool` -- true if `out` and `outlen` have been updated to point to a pending config message;
///   false if there is no pending config message.
LIBSESSION_EXPORT bool groups_keys_pending_config(
        const config_group_keys* conf, const unsigned char** out, size_t* outlen)
        __attribute__((warn_unused_result));

/// API: groups/groups_keys_load_message
///
/// Loads a key config message downloaded from the swarm, and loads the key into the info/member
/// configs.
///
/// Such messages should be processed via this method *before* attempting to load config messages
/// downloaded from an info/members namespace.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `data` -- [in] Pointer to the incoming key config message
/// - `datalen` -- [in] length of `data`
/// - `timestamp_ms` -- [in] the timestamp (from the swarm) of the message
/// - `info` -- [in] the info config object to update with new keys, if needed
/// - `members` -- [in] the members config object to update with new keys, if needed
///
/// Outputs:
/// Returns `true` if the message was parsed successfully (whether or not any new keys were
/// decrypted or loaded).  Returns `false` on failure to parse (and sets `conf->last_error`).
LIBSESSION_EXPORT bool groups_keys_load_message(
        config_group_keys* conf,
        const unsigned char* data,
        size_t datalen,
        int64_t timestamp_ms,
        config_object* info,
        config_object* members) __attribute__((warn_unused_result));

/// API: groups/groups_keys_needs_rekey
///
/// Checks whether a rekey is required (for instance, because of key generation conflict).  Note
/// that this is *not* a check for when members changed (such rekeys are up to the caller to
/// manage), but mergely whether a rekey is needed after loading one or more config messages.
///
/// See the C++ Keys::needs_rekey and Keys::rekey descriptions for more details.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `bool` -- `true` if `rekey()` needs to be called, `false` otherwise.
LIBSESSION_EXPORT bool groups_keys_needs_rekey(const config_group_keys* conf)
        __attribute__((warn_unused_result));

/// API: groups/groups_keys_needs_dump
///
/// Checks whether a groups_keys_dump needs to be called to save state.  This is analagous to
/// config_dump, but specific for the group keys object.  The value becomes false as soon as
/// `groups_keys_dump` is called, and remains false until the object's state is mutated (e.g. by
/// rekeying or loading new config messages).
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `bool` -- `true` if a dump is needed, `false` otherwise.
LIBSESSION_EXPORT bool groups_keys_needs_dump(const config_group_keys* conf)
        __attribute__((warn_unused_result));

/// API: groups/groups_keys_dump
///
/// Produces a dump of the keys object state to be stored by the application to later restore the
/// object by passing the dump into the constructor.  This is analagous to config_dump, but specific
/// for the group keys object.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `out` -- [out] Pointer-pointer to a data buffer; this will be set to a newly malloc'd pointer
///   containing the dump data.  The caller is responsible for freeing the data when done!
/// - `outlen` -- [out] Pointer to a size_t where the length of `out` will be stored.
LIBSESSION_EXPORT void groups_keys_dump(
        config_group_keys* conf, unsigned char** out, size_t* outlen);

/// API: groups/groups_keys_encrypt_message
///
/// Encrypts a message using the most recent group encryption key of this object.  The message will
/// be compressed (if that reduces the size) before being encrypted.  Decryption (and decompression,
/// if compression was applied) is performed by passing such a message into
/// groups_keys_decrypt_message.
///
/// Note: this method can fail if there are no encryption keys at all, or if the incoming message
/// decompresses to a huge value (more than 1MB).  If it fails then `ciphertext_out` is set to NULL
/// and should not be read or free()d.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `plaintext_in` -- [in] Pointer to a data buffer containing the unencrypted data.
/// - `plaintext_len` -- [in] Length of `plaintext_in`
/// - `ciphertext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   encrypted data written to it, and then the pointer to that buffer is stored here.  This
///   buffer must be `free()`d by the caller when done with it!
/// - `ciphertext_len` -- [out] Pointer to a size_t where the length of `ciphertext_out` is stored.
LIBSESSION_EXPORT void groups_keys_encrypt_message(
        const config_group_keys* conf,
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len);

/// API: groups/groups_keys_decrypt_message
///
/// Attempts to decrypt a message using all of the known active encryption keys of this object.  The
/// message will be decompressed after decryption, if required.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `ciphertext_in` -- [in] Pointer to a data buffer containing the encrypted data (as was
///   produced by `groups_keys_encrypt_message`).
/// - `ciphertext_len` -- [in] Length of `ciphertext_in`
/// - `plaintext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   decrypted/decompressed data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it!
/// - `plaintext_len` -- [out] Pointer to a size_t where the length of `plaintext_out` is stored.
///
/// Outputs:
/// - `bool` -- True if the message was successfully decrypted, false if decryption (or parsing or
///   decompression) failed with all of our known keys.
LIBSESSION_EXPORT bool groups_keys_decrypt_message(
        const config_group_keys* conf,
        const unsigned char* cipherext_in,
        size_t cipherext_len,
        unsigned char** plaintext_out,
        size_t* plaintext_len);

#ifdef __cplusplus
}  // extern "C"
#endif
