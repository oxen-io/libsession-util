#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "../state.h"
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

/// API: contacts/state_get_contact
///
/// Fills `contact` with the contact info given a session ID (specified as a null-terminated hex
/// string), if the contact exists, and returns true.  If the contact does not exist then `contact`
/// is left unchanged and false is returned.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `contact` -- [out] the contact info data
/// - `session_id` -- [in] null terminated hex string
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Output:
/// - `bool` -- Returns true if contact exsts
LIBSESSION_EXPORT bool state_get_contact(
        const state_object* state, contacts_contact* contact, const char* session_id, char* error)
        __attribute__((warn_unused_result));

/// API: contacts/state_get_or_construct_contact
///
/// Same as the above `state_get_contact()` except that when the contact does not exist, this sets
/// all the contact fields to defaults and loads it with the given session_id.
///
/// Returns true as long as it is given a valid session_id.  A false return is considered an error,
/// and means the session_id was not a valid session_id.
///
/// This is the method that should usually be used to create or update a contact, followed by
/// setting fields in the contact, and then giving it to state_set_contact().
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
/// - `contact` -- [out] the contact info data
/// - `session_id` -- [in] null terminated hex string
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Output:
/// - `bool` -- Returns true if contact exsts
LIBSESSION_EXPORT bool state_get_or_construct_contact(
        const state_object* state, contacts_contact* contact, const char* session_id, char* error)
        __attribute__((warn_unused_result));

/// API: contacts/state_set_contact
///
/// Adds or updates a contact from the given contact info struct.
///
/// Inputs:
/// - `state` -- [in, out] Pointer to the mutable state object
/// - `contact` -- [in] Pointer containing the contact info data
LIBSESSION_EXPORT void state_set_contact(
        mutable_state_user_object* state, const contacts_contact* contact);

// NB: wrappers for set_name, set_nickname, etc. C++ methods are deliberately omitted as they would
// save very little in actual calling code.  The procedure for updating a single field without them
// is simple enough; for example to update `approved` and leave everything else unchanged:
//
// contacts_contact c;
// if (state_get_or_construct_contact(conf, &c, some_session_id)) {
//     const char* new_nickname = "Joe";
//     c.approved = new_nickname;
//     contacts_set_or_create(conf, &c);
// } else {
//     // some_session_id was invalid!
// }

/// API: contacts/state_erase_contact
///
/// Erases a contact from the contact list.  session_id is in hex.  Returns true if the contact was
/// found and removed, false if the contact was not present.  You must not call this during
/// iteration; see details below.
///
/// Inputs:
/// - `state` -- [in, out] Pointer to the mutable state object
/// - `session_id` -- [in] Text containing null terminated hex string
///
/// Outputs:
/// - `bool` -- True if erasing was successful
LIBSESSION_EXPORT bool state_erase_contact(
        mutable_state_user_object* state, const char* session_id);

/// API: contacts/state_size_contacts
///
/// Returns the number of contacts.
///
/// Inputs:
/// - `state` -- input - Pointer to the state object
///
/// Outputs:
/// - `size_t` -- number of contacts
LIBSESSION_EXPORT size_t state_size_contacts(const state_object* state);

typedef struct contacts_iterator {
    void* _internals;
} contacts_iterator;

/// API: contacts/contacts_iterator_new
///
/// Starts a new iterator.
///
/// Functions for iterating through the entire contact list, in sorted order.  Intended use is:
///
///     contacts_contact c;
///     contacts_iterator *it = contacts_iterator_new(state);
///     for (; !contacts_iterator_done(it, &c); contacts_iterator_advance(it)) {
///         // c.session_id, c.nickname, etc. are loaded
///     }
///     contacts_iterator_free(it);
///
/// It is NOT permitted to add/remove/modify records while iterating.
///
/// Inputs:
/// - `state` -- [in] Pointer to the state object
///
/// Outputs:
/// - `contacts_iterator*` -- pointer to the iterator
LIBSESSION_EXPORT contacts_iterator* contacts_iterator_new(const state_object* state);

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
