#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

/// API: state/state_create
///
/// Constructs a new state which generates it's own random ed25519 key pair.
///
/// When done with the object the `state_object` must be destroyed by passing the pointer to
/// state_free().
///
/// Inputs:
/// - `state` -- [out] Pointer to the state object
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `int` -- Returns 0 on success; returns a non-zero error code and write the exception message
/// as a C-string into `error` (if not NULL) on failure.
LIBSESSION_EXPORT bool state_create(state_object** state, char* error)
        __attribute__((warn_unused_result));

/// API: state/state_create
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
/// - `conf` -- [in] Pointer to config_object object
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
/// void log(config_log_level lvl, const char* msg, void* ctx);
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
        state_object* state, void (*callback)(config_log_level, const char*, void*), void* ctx);

/// API: state/state_set_send_callback
///
/// Takes a function pointer and a context pointer (which can be NULL if not needed).  The given
/// function pointer will be invoked whenever a config `needs_push` as long as the state isn't
/// suppressing send events.
///
/// The function must have signature:
///
/// void callback(const char*, const unsigned char*, size_t, const unsigned char*, size_t, void*);
///
/// Can be called with callback set to NULL to clear an existing hook.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `callback` -- [in] Callback function
/// - `ctx` --- [in, optional] Pointer to an optional context. Set to NULL if unused
LIBSESSION_EXPORT bool state_set_send_callback(
        state_object* state,
        void (*callback)(
                const char*, const unsigned char*, size_t, const unsigned char*, size_t, void*),
        void* ctx);

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
LIBSESSION_EXPORT int64_t state_network_offset(state_object* state);

/// API: state/state_suppress_hooks_start
///
/// This will suppress the `send` and `store` hooks until `state_suppress_hooks_stop` is called and
/// should be used when making multiple config changes to avoid sending and storing unnecessary
/// partial changes.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `send` -- [in] controls whether the `send` hook should be suppressed.
/// - `store` -- [in] controls whether the `store` hook should be suppressed.
/// - `pubkey_hex` -- [in] pubkey to suppress changes for (in hex, with prefix - 66
/// bytes). If none is provided then all changes for all configs will be supressed.
LIBSESSION_EXPORT bool state_suppress_hooks_start(
        state_object* state, bool send, bool store, const char* pubkey_hex);

/// API: state/state_suppress_hooks_stop
///
/// This will stop suppressing the `send` and `store` hooks. When this is called, if there are
/// any pending changes, the `send` and `store` hooks will immediately be called.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `send` -- [in] controls whether the `send` hook should no longer be suppressed.
/// - `store` -- [in] controls whether the `store` hook should no longer be suppressed.
/// - `pubkey_hex` -- [in] pubkey to stop suppressing changes for (in hex, with prefix - 66 bytes).
/// If the value provided doesn't match a entry created by `state_suppress_hooks_start` those
/// changes will continue to be suppressed. If none is provided then the hooks for all configs
/// with pending changes will be triggered.
LIBSESSION_EXPORT bool state_suppress_hooks_stop(
        state_object* state, bool send, bool store, const char* pubkey_hex);

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
        config_string_list** successful_hashes);

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
        state_object* state, const char* pubkey_hex_, config_string_list** current_hashes);

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

/// API: state/state_received_send_response
///
/// Takes the network respons and request context from sending the data from the `send` hook and
/// processes the response updating the state as needed.
///
/// Inputs:
/// - `state` -- [in] Pointer to state_object object
/// - `pubkey_hex` -- [in] optional pubkey the dump is associated to (in hex, with prefix - 66
/// bytes). Required for group dumps.
/// - `response_data` -- [in] Pointer to the response from the swarm after sending the
/// `payload_data`.
/// - `response_data_len` -- [in] Length of the `response_data`.
/// - `request_ctx` -- [in] Pointer to the request context data which was provided by the `send`
/// hook.
/// - `request_ctx_len` -- [in] Length of the `request_ctx`.
LIBSESSION_EXPORT bool state_received_send_response(
        state_object* state,
        const char* pubkey_hex,
        unsigned char* response_data,
        size_t response_data_len,
        unsigned char* request_ctx,
        size_t request_ctx_len);

/// User Profile functions

/// API: state/state_get_profile_name
///
/// Returns a pointer to the currently-set name (null-terminated), or NULL if there is no name at
/// all.  Should be copied right away as the pointer may not remain valid beyond other API calls.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
///
/// Outputs:
/// - `char*` -- Pointer to the currently-set name as a null-terminated string, or NULL if there is
/// no name
LIBSESSION_EXPORT const char* state_get_profile_name(const state_object* state);

/// API: state/state_set_profile_name
///
/// Sets the user profile name to the null-terminated C string.  Returns 0 on success, non-zero on
/// error (and sets the state_object's error string).
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `name` -- [in] Pointer to the name as a null-terminated C string
LIBSESSION_EXPORT void state_set_profile_name(state_object* state, const char* name);

/// API: state/state_get_profile_pic
///
/// Obtains the current profile pic.  The pointers in the returned struct will be NULL if a profile
/// pic is not currently set, and otherwise should be copied right away (they will not be valid
/// beyond other API calls on this config object).
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
///
/// Outputs:
/// - `user_profile_pic` -- Pointer to the currently-set profile pic
LIBSESSION_EXPORT user_profile_pic state_get_profile_pic(const state_object* state);

/// API: state/state_set_profile_pic
///
/// Sets a user profile
///
/// Inputs:
/// - `state` -- [in] Pointer to the satet object
/// - `pic` -- [in] Pointer to the pic
LIBSESSION_EXPORT void state_set_profile_pic(state_object* state, user_profile_pic pic);

/// API: state/state_get_profile_nts_priority
///
/// Gets the current note-to-self priority level. Will be negative for hidden, 0 for unpinned, and >
/// 0 for pinned (with higher value = higher priority).
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
///
/// Outputs:
/// - `int` -- Returns the priority level
LIBSESSION_EXPORT int state_get_profile_nts_priority(const state_object* state);

/// API: state/state_set_profile_nts_priority
///
/// Sets the current note-to-self priority level. Set to -1 for hidden; 0 for unpinned, and > 0 for
/// higher priority in the conversation list.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `priority` -- [in] Integer of the priority
LIBSESSION_EXPORT void state_set_profile_nts_priority(state_object* state, int priority);

/// API: state/state_get_profile_nts_expiry
///
/// Gets the Note-to-self message expiry timer (seconds).  Returns 0 if not set.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
///
/// Outputs:
/// - `int` -- Returns the expiry timer in seconds. Returns 0 if not set
LIBSESSION_EXPORT int state_get_profile_nts_expiry(const state_object* state);

/// API: state/state_set_profile_nts_expiry
///
/// Sets the Note-to-self message expiry timer (seconds).  Setting 0 (or negative) will clear the
/// current timer.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `expiry` -- [in] Integer of the expiry timer in seconds
LIBSESSION_EXPORT void state_set_profile_nts_expiry(state_object* state, int expiry);

/// API: state/state_get_profile_blinded_msgreqs
///
/// Returns true if blinded message requests should be retrieved (from SOGS servers), false if they
/// should be ignored.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
///
/// Outputs:
/// - `int` -- Will be -1 if the state does not have the value explicitly set, 0 if the setting is
///   explicitly disabled, and 1 if the setting is explicitly enabled.
LIBSESSION_EXPORT int state_get_profile_blinded_msgreqs(const state_object* state);

/// API: state/state_set_profile_blinded_msgreqs
///
/// Sets whether blinded message requests should be retrieved from SOGS servers.  Set to 1 (or any
/// positive value) to enable; 0 to disable; and -1 to clear the setting.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `enabled` -- [in] true if they should be enabled, false if disabled
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void state_set_profile_blinded_msgreqs(state_object* state, int enabled);

#ifdef __cplusplus
}  // extern "C"
#endif
