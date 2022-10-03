#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/// Structs for data exchange.  The values in these structs should be considered read-only and not
/// changed directly: they are, generally, copies or pointers into the underlying C++ data structure
/// (carried in the `_internal` pointer of each one), but changes do not propagate back into the
/// proper object.  Changing these, rather, requires other APIs.

struct closed_group_info {
    void* _internal;

    // null-terminated (C string) name.
    const char* name;

    /// Optional null-terminated (C string) description.  Will be NULL if there is no description
    /// (note that empty-description and no-description are different).
    const char* description;

    /// Optional profile picture url; either a null-terminated C string, or NULL if no profile
    /// picture is set.
    const char* profile_picture_url;
    /// Profile description key; this is bytes that *may* contain NULLs (use ..._key_len).  Will be
    /// NULL if no profile picture is set, or the profile picture is not encrypted.
    const char* profile_picture_key;

    /// length of profile_picture_key bytes.  -1 if no profile picture key is set.
    int profile_picture_key_len;

    /// Disappearing messages setting.  This is an integer where:
    /// 0 = none (no disappearing messages)
    /// 1 = delete x time after send
    /// 2 = delete x time after reading (currently not implemented for closed groups)
    int disappear_mode;

    /// The timer (in seconds) for disappearing messages mode.  Will be 0 if mode is none.
    int disappear_timer;
};

void free_closed_group_info(closed_group_info* info);

struct closed_group_member {
    // The member's session_id, in the usual 66-byte hex representation.  Null terminated.
    const char* session_id;

    // The member's role; 0 = regular member, 1 = admin.
    int role;
};

struct closed_group_members {
    void* _internal;

    // Array of members of the group
    const closed_group_member* members;

    // Number of members in the array
    const size_t members_len;
};

#ifdef __cplusplus
}  // extern "C"
#endif
