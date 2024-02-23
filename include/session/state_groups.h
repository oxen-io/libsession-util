#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config/groups/members.h"
#include "config/namespaces.h"
#include "config/profile_pic.h"
#include "export.h"
#include "state.h"

/// API: groups/state_create_group
///
/// Creates a new group with the provided values defining the initial state. Triggers the callback
/// upon success or error, if an error occurred the `error` value will be populated, otherwise the
/// `group_id` and `group_sk` will be populated.
///
/// This function will add the updated group into the user groups config and setup the initial group
/// configs. The '_send' and '_store' hooks will be triggered for the newly created/updated config
/// messages.
///
/// Note: This function **does not** send invitations to the group members so the clients will still
/// need to do so. Any members provided to this funciton will be included in the initial keys
/// generation.
///
/// Inputs:
/// - `state` -- Pointer to the mutable state object
/// - `name` -- the name of the group.
/// - `name_len` -- the length of the 'name'
/// - `description` -- optional description for the group.
/// - `description_len` -- the length of the 'description'.
/// - `pic` -- optional display picture for the group.
/// - `members` -- initial members to be added to the group.
/// - `members_len` -- the length of the 'members' array.
/// - `callback` -- a callback to be triggered upon success/failure of the group creation.
/// - `ctx` -- Pointer to an optional context. Set to NULL if unused
LIBSESSION_EXPORT void state_create_group(
        state_object* state,
        const char* name,
        size_t name_len,
        const char* description,
        size_t description_len,
        const user_profile_pic pic,
        const state_group_member* members,
        const size_t members_len,
        void (*callback)(
                const char* group_id,
                unsigned const char* group_sk,
                const char* error,
                const size_t error_len,
                void* ctx),
        void* ctx);

/// API: groups/state_approve_group
///
/// Approves a group invitation, this will update the 'invited' flag in the user groups config and
/// create the initial group state.
///
/// Inputs:
/// - `state` -- Pointer to the mutable state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `group_sk` -- optional 64-byte secret key for the group.
LIBSESSION_EXPORT void state_approve_group(
        state_object* state, const char* group_id, unsigned const char* group_sk);

/// API: groups/state_load_group_admin_key
///
/// Loads the admin keys into a group, upgrading the user from a member to an admin within the keys
/// and members objects, and storing the group secret key within the user groups config.
///
/// Inputs:
/// - `state` -- Pointer to the mutable state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `seed` -- pointer to the 32-byte seed.
///
/// Outputs:
/// - `true` if the member has been upgraded to admin status, or was already admin status; `false`
///   if the given seed value does not match the group's public key.  If this returns `true` then
///   after the call a call to `state_is_group_admin` would also return `true`.
LIBSESSION_EXPORT bool state_load_group_admin_key(
        state_object* state, const char* group_id, unsigned const char* seed);

/// API: groups/state_add_group_members
///
/// Adds members to Members for the group and performs either a key rotation or a key supplement.
/// Only admins can call this.
///
/// Invite details, auth signature, etc. will still need to be sent separately to the new user.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object.
/// - `group_id` -- [in] the group id/pubkey, in hex, beginning with "03".
/// - `supplemental_rotation` -- [in] flag to control whether a supplemental (when true) or full
/// (when false) key rotation should be performed. Doing a supplemental rotation will distributes
/// the existing active keys so that the new members can access existing key, configs and messages.
/// - `members` -- [in] array of members to add to the group.
/// - `members_len` -- [in] length of the `members` array
/// - `callback` -- [in] Callback function called once the send process completes
/// - `ctx` --- [in, optional] Pointer to an optional context. Set to NULL if unused
LIBSESSION_EXPORT void state_add_group_members(
        state_object* state,
        const char* group_id,
        const bool supplemental_rotation,
        const state_group_member** members,
        const size_t members_len,
        void (*callback)(const char* error, void* ctx),
        void* ctx);

/// API: groups/state_erase_group
///
/// Removes the group state and, if specified, removes the group from the user groups config.
///
/// Inputs:
/// - `state` -- Pointer to the mutable state object
/// - `group_id` -- the group id/pubkey, in hex, beginning with "03".
/// - `remove_user_record` -- flag to indicate whether the user groups entry should be removed.
LIBSESSION_EXPORT void state_erase_group(
        state_object* state, const char* group_id, bool remove_user_record);

#ifdef __cplusplus
}  // extern "C"
#endif
