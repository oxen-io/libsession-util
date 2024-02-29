#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "../state.h"
#include "profile_pic.h"

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
/// - `state` -- [in] Pointer to the mutable state object
/// - `name` -- [in] Pointer to the name as a null-terminated C string
LIBSESSION_EXPORT void state_set_profile_name(mutable_user_state_object* state, const char* name);

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
/// - `state` -- [in] Pointer to the mutable state object
/// - `pic` -- [in] Pointer to the pic
LIBSESSION_EXPORT void state_set_profile_pic(
        mutable_user_state_object* state, user_profile_pic pic);

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
/// - `state` -- [in] Pointer to the mutable state object
/// - `priority` -- [in] Integer of the priority
LIBSESSION_EXPORT void state_set_profile_nts_priority(
        mutable_user_state_object* state, int priority);

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
LIBSESSION_EXPORT void state_set_profile_nts_expiry(mutable_user_state_object* state, int expiry);

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
/// - `state` -- [in] Pointer to the mutable state object
/// - `enabled` -- [in] true if they should be enabled, false if disabled
LIBSESSION_EXPORT void state_set_profile_blinded_msgreqs(
        mutable_user_state_object* state, int enabled);

#ifdef __cplusplus
}  // extern "C"
#endif
