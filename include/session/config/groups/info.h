#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "../../state.h"
#include "../profile_pic.h"
#include "../util.h"

LIBSESSION_EXPORT extern const size_t GROUP_INFO_NAME_MAX_LENGTH;
LIBSESSION_EXPORT extern const size_t GROUP_INFO_DESCRIPTION_MAX_LENGTH;

/// API: groups_info/state_get_group_name
///
/// Returns a pointer to the currently-set name (null-terminated), or NULL if there is no name at
/// all.  Should be copied right away as the pointer may not remain valid beyond other API calls.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `name` -- [out] the pointer to a buffer in which we will write the null-terminated name
/// string. This must be a
///   buffer of at least 'GROUP_INFO_NAME_MAX_LENGTH' bytes.
///
/// Outputs:
/// - `bool` -- Flag indicating whether it was able to successfully retrieve the group name
LIBSESSION_EXPORT bool state_get_group_name(
        const state_object* state, const char* group_id, char* name);

/// API: groups_info/state_set_group_name
///
/// Sets the group's name to the null-terminated C string.  Returns 0 on success, non-zero on
/// error (and sets the state_object's error string).
///
/// If the given name is longer than GROUP_INFO_NAME_MAX_LENGTH (100) bytes then it will be
/// truncated.
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
/// - `name` -- [in] Pointer to the name as a null-terminated C string
LIBSESSION_EXPORT void state_set_group_name(mutable_group_state_object* state, const char* name);

/// API: groups_info/state_get_group_description
///
/// Returns a pointer to the currently-set description (null-terminated), or NULL if there is no
/// description at all.  Should be copied right away as the pointer may not remain valid beyond
/// other API calls.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `description` -- [out] the pointer to a buffer in which we will write the null-terminated
/// description string. This must be a
///   buffer of at least 'GROUP_INFO_DESCRIPTION_MAX_LENGTH' bytes.
///
/// Outputs:
/// - `bool` -- Flag indicating whether it was able to successfully retrieve the group description
LIBSESSION_EXPORT bool state_get_group_description(
        const state_object* state, const char* group_id, char* description);

/// API: groups_info/state_set_group_description
///
/// Sets the group's description to the null-terminated C string.  Returns 0 on success, non-zero on
/// error (and sets the state_object's error string).
///
/// If the given description is longer than GROUP_INFO_DESCRIPTION_MAX_LENGTH (2000) bytes then it
/// will be truncated.
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
/// - `description` -- [in] Pointer to the description as a null-terminated C string
LIBSESSION_EXPORT void state_set_group_description(
        mutable_group_state_object* state, const char* description);

/// API: groups_info/state_get_group_pic
///
/// Obtains the current profile pic.  The pointers in the returned struct will be NULL if a profile
/// pic is not currently set, and otherwise should be copied right away (they will not be valid
/// beyond other API calls on this config object).
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `description` -- [out] the pointer that will be set to the current profile pic (despite the
/// "user_profile" in
///   the struct name, this is the group's profile pic).
///
/// Outputs:
/// - `bool` -- Flag indicating whether it was able to successfully retrieve the group profile pic
LIBSESSION_EXPORT bool state_get_group_pic(
        const state_object* state, const char* group_id, user_profile_pic* pic);

/// API: groups_info/state_set_group_pic
///
/// Sets a user profile
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
/// - `pic` -- [in] Pointer to the pic
LIBSESSION_EXPORT void state_set_group_pic(mutable_group_state_object* state, user_profile_pic pic);

/// API: groups_info/state_get_group_expiry_timer
///
/// Gets the group's message expiry timer (seconds).  Returns 0 if not set.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `timer` -- [out] Pointer that will be set to the expiry timer in seconds.
///
/// Outputs:
/// - `bool` -- Flag indicating whether it was able to successfully retrieve the group expiry timer
LIBSESSION_EXPORT bool state_get_group_expiry_timer(
        const state_object* state, const char* group_id, int* timer);

/// API: groups_info/state_set_group_expiry_timer
///
/// Sets the group's message expiry timer (seconds).  Setting 0 (or negative) will clear the current
/// timer.
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
/// - `expiry` -- [in] Integer of the expiry timer in seconds
LIBSESSION_EXPORT void state_set_group_expiry_timer(mutable_group_state_object* state, int expiry);

/// API: groups_info/state_get_group_created
///
/// Returns the timestamp (unix time, in seconds) when the group was created.  Returns 0 if unset.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `created` -- [out] Pointer that will be set to the unix timestamp when the group was created
/// (if set by an admin).
///
/// Outputs:
/// - `bool` -- Flag indicating whether it was able to successfully retrieve the group created
/// timestamp
LIBSESSION_EXPORT bool state_get_group_created(
        const state_object* state, const char* group_id, int64_t* created);

/// API: groups_info/state_set_group_created
///
/// Sets the creation time (unix timestamp, in seconds) when the group was created.  Setting 0
/// clears the value.
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
/// - `ts` -- [in] the unix timestamp, or 0 to clear a current value.
LIBSESSION_EXPORT void state_set_group_created(mutable_group_state_object* state, int64_t ts);

/// API: groups_info/state_get_group_delete_before
///
/// Returns the delete-before timestamp (unix time, in seconds); clients should delete all messages
/// from the group with timestamps earlier than this value, if set.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `delete_before` -- [out] Pointer that will be set to the unix timestamp before which messages
/// should be deleted.  Returns 0 if not set.
///
/// Outputs:
/// - `bool` -- Flag indicating whether it was able to successfully retrieve the group deleted
/// before value
LIBSESSION_EXPORT bool state_get_group_delete_before(
        const state_object* state, const char* group_id, int64_t* delete_before);

/// API: groups_info/state_set_group_delete_before
///
/// Sets the delete-before time (unix timestamp, in seconds) before which messages should be
/// deleted.  Setting 0 clears the value.
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
/// - `ts` -- [in] the unix timestamp, or 0 to clear a current value.
LIBSESSION_EXPORT void state_set_group_delete_before(mutable_group_state_object* state, int64_t ts);

/// API: groups_info/state_get_group_attach_delete_before
///
/// Returns the delete-before timestamp (unix time, in seconds) for attachments; clients should drop
/// all attachments from messages from the group with timestamps earlier than this value, if set.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `delete_before` -- [out] Pointer that will be set to the unix timestamp before which message
/// attachments should be deleted.  Returns 0 if not set.
///
/// Outputs:
/// - `bool` -- Flag indicating whether it was able to successfully retrieve the group deleted
/// before value
LIBSESSION_EXPORT bool state_get_group_attach_delete_before(
        const state_object* state, const char* group_id, int64_t* delete_before);

/// API: groups_info/state_set_group_attach_delete_before
///
/// Sets the delete-before time (unix timestamp, in seconds) for attachments; attachments should be
/// dropped from messages older than this value.  Setting 0 clears the value.
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
/// - `ts` -- [in] the unix timestamp, or 0 to clear a current value.
LIBSESSION_EXPORT void state_set_group_attach_delete_before(
        mutable_group_state_object* state, int64_t ts);

/// API: groups_info/state_group_is_destroyed
///
/// Returns true if this group has been marked destroyed by an admin, which indicates to a receiving
/// client that they should destroy it locally.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
///
/// Outputs:
/// - `true` if the group has been nuked, `false` otherwise.
LIBSESSION_EXPORT bool state_group_is_destroyed(const state_object* state, const char* group_id);

/// API: groups_info/state_destroy_group
///
/// Nukes a group from orbit.  This is permanent (i.e. there is no removing this setting once set).
///
/// Inputs:
/// - `state` -- [in] Pointer to the mutable state object
LIBSESSION_EXPORT void state_destroy_group(mutable_group_state_object* state);

#ifdef __cplusplus
}  // extern "C"
#endif
