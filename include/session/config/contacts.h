#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "expiring.h"
#include "notify.h"
#include "profile_pic.h"
#include "util.h"

// Maximum length of a contact name/nickname, in bytes (not including the null terminator).
LIBSESSION_EXPORT extern const size_t CONTACT_MAX_NAME_LENGTH;

typedef struct contacts_contact {
    char session_id[67];  // in hex; 66 hex chars + null terminator.

    // These two will be 0-length strings when unset:
    char name[101];
    char nickname[101];
    user_profile_pic profile_pic;

    bool approved;
    bool approved_me;
    bool blocked;

    int priority;
    CONVO_NOTIFY_MODE notifications;
    int64_t mute_until;

    CONVO_EXPIRATION_MODE exp_mode;
    int exp_seconds;

    int64_t created;  // unix timestamp (seconds)

} contacts_contact;

typedef struct contacts_iterator {
    void* _internals;
} contacts_iterator;

/// API: contacts/contacts_iterator_free
///
/// Frees an iterator once no longer needed.
///
/// Inputs:
/// - `it` -- [in] Pointer to the contacts_iterator
LIBSESSION_EXPORT void contacts_iterator_free(contacts_iterator* it);

/// API: contacts/contacts_iterator_done
///
/// Returns true if iteration has reached the end.  Otherwise `c` is populated and false is
/// returned.
///
/// Inputs:
/// - `it` -- [in] Pointer to the contacts_iterator
/// - `c` -- [out] Pointer to the contact, will be populated if false
///
/// Outputs:
/// - `bool` -- True if iteration has reached the end
LIBSESSION_EXPORT bool contacts_iterator_done(contacts_iterator* it, contacts_contact* c);

/// API: contacts/contacts_iterator_advance
///
/// Advances the iterator.
///
/// Inputs:
/// - `it` -- [in] Pointer to the contacts_iterator
LIBSESSION_EXPORT void contacts_iterator_advance(contacts_iterator* it);

#ifdef __cplusplus
}  // extern "C"
#endif
