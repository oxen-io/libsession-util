#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "config/namespaces.h"
#include "config/profile_pic.h"
#include "export.h"

typedef struct state_object {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;

    // When an error occurs in the C API this string will be set to the specific error message.  May
    // be empty.
    const char* last_error;

    // Sometimes used as the backing buffer for `last_error`.  Should not be touched externally.
    char _error_buf[256];
} state_object;

typedef struct mutable_user_state_object {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;
} mutable_user_state_object;

typedef struct mutable_group_state_object {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;
} mutable_group_state_object;

typedef struct state_namespaced_dump {
    NAMESPACE namespace_;
    const char* pubkey_hex;
    const unsigned char* data;
    size_t datalen;
} state_namespaced_dump;

typedef struct state_config_message {
    NAMESPACE namespace_;
    const char* hash;
    uint64_t timestamp_ms;
    const unsigned char* data;
    size_t datalen;
} state_config_message;

typedef struct state_send_response {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;
} state_send_response;

typedef enum state_log_level {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR
} state_log_level;

/// API: state/state_init
///
/// Constructs a new state which generates it's own random ed25519 key pair.
///
/// When done with the object the `state_object` must be destroyed by passing the pointer to
/// state_free().
///
/// Inputs:
/// - `state` -- [out] Pointer to the state object
/// - `ed25519_secretkey` -- [in] must be the 32-byte secret key seed value.  (You can also pass the
/// pointer to the beginning of the 64-byte value libsodium calls the "secret key" as the first 32
/// bytes of that are the seed).  This field cannot be null.
/// - `dumps` -- [in] pointer to an array of `state_namespaced_dump` which should include all dumps
/// which should be loaded into the state.
/// - `count` -- [in] number of items in the `dumps` pointer.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `int` -- Returns 0 on success; returns a non-zero error code and write the exception message
/// as a C-string into `error` (if not NULL) on failure.
LIBSESSION_EXPORT bool state_init(
        state_object** state,
        const unsigned char* ed25519_secretkey,
        state_namespaced_dump* dumps,
        size_t count,
        char* error) __attribute__((warn_unused_result));

/// API: state/state_free
///
/// Frees a state object.
///
/// Inputs:
/// - `conf` -- [in] Pointer to state_object object
LIBSESSION_EXPORT void state_free(state_object* state);

/// API: state/state_load
///
/// Loads a dump into the state. Calling this will replace the current config instance with
/// with a new instance initialised with the provided dump. The configs must be loaded according
/// to the order 'namespace_load_order' in 'namespaces.hpp' or an exception will be thrown.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `namespace` -- the namespace where config messages for this dump are stored.
/// - `pubkey_hex` -- optional pubkey the dump is associated to (in hex, with prefix - 66
/// bytes). Required for group dumps.
/// - `dump` -- pointer to the binary state data that was previously dumped by calling `dump()` or
/// from the `store` hook.
/// - `dumplen` -- length of `dump`.
LIBSESSION_EXPORT bool state_load(
        state_object* state,
        NAMESPACE namespace_,
        const char* pubkey_hex,
        const unsigned char* dump,
        size_t dumplen);

/// API: state/state_set_logger
///
/// Sets a logging function; takes the log function pointer and a context pointer (which can be NULL
/// if not needed).  The given function pointer will be invoked with one of the above values, a
/// null-terminated c string containing the log message, and the void* context object given when
/// setting the logger (this is for caller-specific state data and won't be touched).
///
/// The logging function must have signature:
///
/// void log(state_log_level lvl, const char* msg, void* ctx);
///
/// Can be called with callback set to NULL to clear an existing logger.
///
/// The config object itself has no log level: the caller should filter by level as needed.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `callback` -- [in] Callback function
/// - `ctx` --- [in, optional] Pointer to an optional context. Set to NULL if unused
LIBSESSION_EXPORT void state_set_logger(
        state_object* state, void (*callback)(state_log_level, const char*, void*), void* ctx);

/// API: state/state_set_send_callback
///
/// Takes a function pointer and a context pointer (which can be NULL if not needed).  The given
/// function pointer will be invoked whenever a config `needs_push`. The function pointer contains
/// it's own callback function pointer which should be called by the client when it receives a
/// network response to the original send request.
///
/// Can be called with callback set to NULL to clear an existing hook.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `callback` -- [in] Callback function
/// - `app_ctx` --- [in, optional] Pointer to an optional context. Set to NULL if unused
LIBSESSION_EXPORT bool state_set_send_callback(
        state_object* state,
        void (*callback)(
                const char* pubkey,
                const unsigned char* data,
                size_t data_len,
                bool (*response_cb)(
                        bool success,
                        int16_t status_code,
                        const unsigned char* res,
                        size_t reslen,
                        void* callback_context),
                void* app_ctx,
                void* callback_context),
        void* app_ctx);

/// API: state/state_set_store_callback
///
/// Takes a function pointer and a context pointer (which can be NULL if not needed).  The given
/// function pointer will be invoked whenever a config `needs_dump` as long as the state isn't
/// suppressing store events.
///
/// The function must have signature:
///
/// void callback(NAMESPACE, const char*, uint64_t, const unsigned char*, size_t, void*);
///
/// Can be called with callback set to NULL to clear an existing hook.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `callback` -- [in] Callback function
/// - `ctx` --- [in, optional] Pointer to an optional context. Set to NULL if unused
LIBSESSION_EXPORT bool state_set_store_callback(
        state_object* state,
        void (*callback)(NAMESPACE, const char*, uint64_t, const unsigned char*, size_t, void*),
        void* ctx);

/// API: state/state_set_service_node_offset
///
/// Updates the state service node offset.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `offset_ms` -- [in] the delta between the current device time and service node time in the
/// most recent API response
LIBSESSION_EXPORT void state_set_service_node_offset(state_object* state, int64_t offset_ms);

/// API: state/state_network_offset
///
/// Retrieves the state service node offset.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
///
/// Outputs:
/// - `int64_t` -- the delta between the current device time and service node time in the
/// most recent API response
LIBSESSION_EXPORT int64_t state_network_offset(const state_object* state);

/// API: state/state_has_pending_send
///
/// Returns whether the state currently has local changes which are waiting to be sent.
///
/// Inputs:
/// - `state` -- [in] Pointer to state object
///
/// Outputs:
/// - `bool` -- Flag indicating whether the state has local changes which are waiting to be sent.
LIBSESSION_EXPORT bool state_has_pending_send(const state_object* state);

/// API: state/state_merge
///
/// Takes an pointer to an array of `state_config_message`, sorts them and merges them into the
/// relevant configs.  Allocates a new buffer and sets it in `successful_hashes`.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `pubkey_hex` -- [in] optional pubkey the dump is associated to (in hex, with prefix - 66
/// bytes). Required for group dumps.
/// - `configs` -- [in] Pointer to an array of `state_config_message` objects
/// - `count` -- [in] Number of objects in `configs`
/// - `successful_hashes` -- [out] Pointer to an array of message hashes that were successfully
/// merged
LIBSESSION_EXPORT bool state_merge(
        state_object* state,
        const char* pubkey_hex_,
        state_config_message* configs,
        size_t count,
        session_string_list** successful_hashes);

/// API: state/state_current_hashes
///
/// The current config hashes; this can be empty if the current hashes are unknown or the current
/// state is not clean (i.e. a push is needed or pending).
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `pubkey_hex` -- [in] optional pubkey to retrieve the hashes for (in hex, with prefix - 66
/// bytes). Required for group hashes.
/// - `current_hashes` -- [out] Pointer to an array of the current config hashes
LIBSESSION_EXPORT bool state_current_hashes(
        state_object* state, const char* pubkey_hex_, session_string_list** current_hashes);

/// API: state/state_current_seqno
///
/// The current config seqno; this will return the updated seqno if there is a pending push. If
/// an invalid pubkey is provided when trying to retrieve for a group namespace then '-1' is
/// returned.
///
/// Inputs:
/// - `state` -- [in] Pointer to state object
/// - `pubkey_hex` -- [in] optional pubkey to retrieve the hashes for (in hex, with prefix - 66
/// bytes). Required for group namespaces.
/// - `namespace` -- [in] The namespace to retrieve the seqno for.
///
/// Outputs:
/// - `seqno_t` -- The seqno for the config state associated with the given pubkey and namespace (or
/// -1 if invalid).
LIBSESSION_EXPORT seqno_t
state_current_seqno(state_object* state, const char* pubkey_hex, NAMESPACE namespace_);

/// API: state/state_dump
///
/// Returns a bt-encoded dict containing the dumps of each of the current config states for
/// storage in the database; the values in the dict would individually get passed into `load` to
/// reconstitute the object (including the push/not pushed status).  Resets the `needs_dump()`
/// flag to false.  Allocates a new buffer and sets
/// it in `out` and the length in `outlen`.  Note that this is binary data, *not* a null-terminated
/// C string.
///
/// NB: It is the caller's responsibility to `free()` the buffer when done with it.
///
/// Immediately after this is called `state_needs_dump` will start returning falst (until the
/// configuration is next modified).
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `full_dump` -- [in] Flag when true the returned bt-encoded dict will include dumps for the
/// entire state, even if they would normally return `false` for `needs_dump()`.
/// - `out` -- [out] Pointer to the output location
/// - `outlen` -- [out] Length of output
LIBSESSION_EXPORT bool state_dump(
        state_object* state, bool full_dump, unsigned char** out, size_t* outlen);

/// API: state/state_dump_namespace
///
/// Returns a binary dump of the current state of the config object for the specified namespace and
/// pubkey.  This dump can be used to resurrect the object at a later point (e.g. after a restart).
/// Allocates a new buffer and sets it in `out` and the length in `outlen`.  Note that this is
/// binary data, *not* a null-terminated C string.
///
/// NB: It is the caller's responsibility to `free()` the buffer when done with it.
///
/// Immediately after this is called `state_needs_dump` will start returning false (until the
/// configuration is next modified).
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `namespace` -- [in] the namespace where config messages of the desired dump are stored.
/// - `pubkey_hex` -- [in] optional pubkey the dump is associated to (in hex, with prefix - 66
/// bytes). Required for group dumps.
/// - `out` -- [out] Pointer to the output location
/// - `outlen` -- [out] Length of output
LIBSESSION_EXPORT bool state_dump_namespace(
        state_object* state,
        NAMESPACE namespace_,
        const char* pubkey_hex,
        unsigned char** out,
        size_t* outlen);

/// API: state/state_get_keys
///
/// Obtains the current group decryption keys.
///
/// Returns a buffer where each consecutive 32 bytes is an encryption key for the object, in
/// priority order (i.e. the key at 0 is the encryption key, and the first decryption key).
///
/// This function is mainly for debugging/diagnostics purposes; most config types have one single
/// key (based on the secret key), and multi-keyed configs such as groups have their own methods for
/// encryption/decryption that are already aware of the multiple keys.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `out` -- [out] pointer to newly malloced key data (a multiple of 32 bytes); the pointer
///   belongs to the caller and must be `free()`d when done with it.
/// - `outlen` -- [out] Pointer where the number of keys will be written (that is: the returned
/// pointer
///   will be to a buffer which has a size of of this value times 32).
LIBSESSION_EXPORT bool state_get_keys(
        state_object* state,
        NAMESPACE namespace_,
        const char* pubkey_hex_,
        unsigned char** out,
        size_t* outlen);

/// API: state/state_mutate_user
///
/// Calls the callback provided with a mutable version of the `state_object` for user changes.
///
/// If an error occurs while the mutation callback is being performed the function will return false
/// and the `state->last_error` will be populated with the error information.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `callback` -- [in] callback to be called with the `mutable_user_state_object` in order to
/// modify the user state.
/// - `ctx` --- [in, optional] Pointer to an optional context. Set to NULL if unused
///
/// Outputs:
/// - `bool` -- Whether the mutation succeeded or not
LIBSESSION_EXPORT bool state_mutate_user(
        state_object* state, void (*callback)(mutable_user_state_object*, void*), void* ctx);

/// API: state/state_mutate_group
///
/// Calls the callback provided with a mutable version of the `state_object` for group changes.
///
/// If an error occurs while the mutation callback is being performed the function will return false
/// and the `state->last_error` will be populated with the error information.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `pubkey_hex` -- [in] the group's public key (in hex, including prefix - 66 bytes)
/// - `callback` -- [in] callback to be called with the `mutable_group_state_object` in order to
/// modify the group state.
/// - `ctx` --- [in, optional] Pointer to an optional context. Set to NULL if unused
///
/// Outputs:
/// - `bool` -- Whether the mutation succeeded or not
LIBSESSION_EXPORT bool state_mutate_group(
        state_object* state,
        const char* pubkey_hex,
        void (*callback)(mutable_group_state_object*, void*),
        void* ctx);

/// API: state/mutable_user_state_set_error_if_empty
///
/// Updates the `state->last_error` value to the provided message if it is currently empty.
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
/// - `err` -- [in] the error value to store in the state
/// - `err_len` -- [in] length of 'err'
LIBSESSION_EXPORT void mutable_user_state_set_error_if_empty(
        mutable_user_state_object* state, const char* err, size_t err_len);

/// API: state/mutable_group_state_set_error_if_empty
///
/// Updates the `state->last_error` value to the provided message if it is currently empty.
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
/// - `err` -- [in] the error value to store in the state
/// - `err_len` -- [in] length of 'err'
LIBSESSION_EXPORT void mutable_group_state_set_error_if_empty(
        mutable_group_state_object* state, const char* err, size_t err_len);

#ifdef __cplusplus
}  // extern "C"
#endif
