#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "base.h"
#include "profile_pic.h"


enum CONVO_EXPIRATION_MODE {
    EXPIRATION_NONE = 0,
    EXPIRATION_AFTER_SEND = 1,
    EXPIRATION_AFTER_READ = 2,
};


typedef struct convo_one_to_one {
    char session_id[67];  // in hex; 66 hex chars + null terminator.

    // milliseconds since unix epoch:
    int64_t last_read;

    // expiration mode & time:
    CONVO_EXPIRATION_MODE exp_mode;
    int64_t exp_minutes;
} convo_one_to_one;

typedef struct convo_open_group {
    const char* base_url; // null-terminated, always lower-case
    const char* room; // null-terminated, always lower-case
    const unsigned char* pubkey; // 32 bytes (not terminated, can contain nulls)
    int64_t last_read; // ms since unix epoch
} convo_open_group;

typedef struct convo_legacy_closed_group {
    char group_id[67];  // in hex; 66 hex chars + null terminator.  Looks just like a Session ID,
                        // though isn't really one.

    int64_t last_read; // ms since unix epoch
} convo_legacy_closed_group;

/// Constructs a conversations config object and sets a pointer to it in `conf`.
///
/// \param ed25519_secretkey must be the 32-byte secret key seed value.  (You can also pass the
/// pointer to the beginning of the 64-byte value libsodium calls the "secret key" as the first 32
/// bytes of that are the seed).  This field cannot be null.
///
/// \param dump - if non-NULL this restores the state from the dumped byte string produced by a past
/// instantiation's call to `dump()`.  To construct a new, empty object this should be NULL.
///
/// \param dumplen - the length of `dump` when restoring from a dump, or 0 when `dump` is NULL.
///
/// \param error - the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Returns 0 on success; returns a non-zero error code and write the exception message as a
/// C-string into `error` (if not NULL) on failure.
///
/// When done with the object the `config_object` must be destroyed by passing the pointer to
/// config_free() (in `session/config/base.h`).
int conversations_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey,
        const unsigned char* dump,
        size_t dumplen,
        char* error) __attribute__((warn_unused_result));

/// Fills `convo` with the conversation info given a session ID (specified as a null-terminated hex
/// string), if the conversation exists, and returns true.  If the conversation does not exist then `convo`
/// is left unchanged and false is returned.
bool convos_get_1to1(const config_object* conf, convo_one_to_one* convo, const char* session_id)
        __attribute__((warn_unused_result));

/// Same as the above except that when the conversation does not exist, this sets all the convo
/// fields to defaults and loads it with the given session_id.
///
/// Returns true as long as it is given a valid session_id.  A false return is considered an error,
/// and means the session_id was not a valid session_id.
///
/// This is the method that should usually be used to create or update a conversation, followed by
/// setting fields in the convo, and then giving it to convos_set().
bool convos_get_or_construct_1to1(
        const config_object* conf, convo_one_to_one* convo, const char* session_id)
        __attribute__((warn_unused_result));

/// Adds or updates a conversation from the given conversation info struct.
void convos_set_1to1(config_object* conf, const convo_one_to_one* convo);

/// open-group versions of the 1-to-1 functions:
///
/// Gets an open group convo info.  `base_url` and `room` are null-terminated c strings; pubkey is
/// 32 bytes.  base_url and room will always be lower-cased (if not already).
bool convos_get_open_group(const config_object* conf, convo_open_group* og, const char* base_url, const char* room, unsigned const char* pubkey)
        __attribute__((warn_unused_result));
bool convos_get_or_construct_open_group(
        const config_object* conf, convo_open_group* convo, const char* base_url, const char* room, unsigned const char* pubkey)
        __attribute__((warn_unused_result));

/// Adds or updates a conversation from the given convo info
void convos_set_1to1(config_object* conf, const convo_one_to_one* convo);
void convos_set_open(config_object* conf, const convo_open_group* convo);
void convos_set_legacy_closed(config_object* conf, const convo_legacy_closed_group* convo);

/// Erases a conversation from the conversation list.  Returns true if the conversation was found
/// and removed, false if the conversation was not present.  You must not call this during
/// iteration; see details below.
bool convos_erase_1to1(config_object* conf, const char* session_id);
bool convos_erase_open(config_object* conf, const char* base_url, const char* room, unsigned const char* pubkey);
bool convos_erase_legacy_closed(config_object* conf, const char* group_id);

/// Returns the number of conversations.
size_t convos_size(const config_object* conf);
/// Returns the number of conversations of the specific type.
size_t convos_size_1to1(const config_object* conf);
size_t convos_size_open(const config_object* conf);
size_t convos_size_legacy_closed(const config_object* conf);

/// Functions for iterating through the entire conversation list.  Intended use is:
///
///     convo_one_to_one c1;
///     convo_open_group c2;
///     convo_legacy_closed_group c3;
///     convos_iterator *it = convos_iterator_new(my_convos);
///     for (; !convos_iterator_done(it); convos_iterator_advance(it)) {
///         if (convo_it_is_1to1(it, &c1)) {
///             // use c1.whatever
///         } else if (convo_it_is_open(it, &c2)) {
///             // use c2.whatever
///         } else if (convo_it_is_legacy_closed(it, &c3)) {
///             // use c3.whatever
///         }
///     }
///     convos_iterator_free(it);
///
/// It is permitted to modify records (e.g. with a call to one of the `convos_set_*` functions) and
/// add records while iterating.
///
/// If you need to remove while iterating then usage is slightly different: you must advance the
/// iteration by calling either convos_iterator_advance if not deleting, or convos_iterator_erase to
/// erase and advance.  Usage looks like this:
///
///     convo_one_to_one c1;
///     convos_iterator *it = convos_iterator_new(my_convos);
///     while (!convos_iterator_done(it)) {
///         if (convo_it_is_1to1(it, &c1)) {
///             bool should_delete = /* ... */;
///             if (should_delete)
///                 convos_iterator_erase(it);
///             else
///                 convos_iterator_advance(it);
///         }
///     }
///     convos_iterator_free(it);
///

typedef struct convos_iterator {
    void* _internals;
} convos_iterator;

// Starts a new iterator that iterates over all conversations.
convos_iterator* convos_iterator_new(const config_object* conf);

// Starts a new iterator that iterates over just one type of conversation.  You still need to use
// `convos_it_is_1to1` (or the alternatives) to load the data in each pass of the loop.  (You can
// safely ignore the bool return value of the `it_is_whatever` function: it will always be true for
// the particular type being iterated over).
convos_iterator* convos_iterator_new_1to1(const config_object* conf);
convos_iterator* convos_iterator_new_open(const config_object* conf);
convos_iterator* convos_iterator_new_legacy_closed(const config_object* conf);

// Frees an iterator once no longer needed.
void convos_iterator_free(convos_iterator* it);

// Returns true if iteration has reached the end.
bool convos_iterator_done(convos_iterator* it);

// Advances the iterator.
void convos_iterator_advance(convos_iterator* it);

// If the current iterator record is a 1-to-1 conversation this sets the details into `c` and
// returns true.  Otherwise it returns false.
bool convos_it_is_1to1(convos_iterator* it, convo_one_to_one* c);

// If the current iterator record is an open group conversation this sets the details into `c` and
// returns true.  Otherwise it returns false.
bool convos_it_is_open(convos_iterator* it, convo_open_group* c);

// If the current iterator record is a legacy closed group conversation this sets the details into
// `c` and returns true.  Otherwise it returns false.
bool convos_it_is_legacy_closed(convos_iterator* it, convo_legacy_closed_group* c);

// Erases the current convo while advancing the iterator to the next convo in the iteration.
void convos_iterator_erase(config_object* conf, convos_iterator* it);

#ifdef __cplusplus
}  // extern "C"
#endif
